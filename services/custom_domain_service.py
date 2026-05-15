"""
CustomDomainService — orchestrates the custom-domain lifecycle.

Composition root for the verifiers, edge provisioner, and repository. Owns
the state machine (``LEGAL_TRANSITIONS``), the per-window quota counters
(Redis-backed when available), and the ``audit.domain.*`` event stream.

Public methods are flag-aware via the ``enabled`` setting — when False,
every mutation refuses with ``DomainQuotaExceededError`` and
``is_allowed_for_caddy`` returns False.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

from bson import ObjectId
from pymongo.errors import DuplicateKeyError

from config import CustomDomainSettings
from errors import (
    DomainAlreadyRegisteredError,
    DomainBlocklistedError,
    DomainQuotaExceededError,
    ForbiddenError,
    InvalidDomainTransitionError,
    NotFoundError,
)
from infrastructure.logging import get_logger
from repositories.blocked_domain_repository import BlockedDomainRepository
from repositories.custom_domain_repository import CustomDomainRepository
from schemas.dto.requests.custom_domain import (
    CreateCustomDomainRequest,
    ListCustomDomainsQuery,
)
from schemas.enums.domain_status import DomainStatus, VerificationMethod
from schemas.models.custom_domain import LEGAL_TRANSITIONS, CustomDomainDoc
from services.edge_provisioner.protocol import EdgeProvisioner
from services.registrar.protocol import HostnameRegistrar
from services.tenant_resolver.protocol import TenantResolver
from services.verifiers.protocol import DomainVerifier, VerificationResult

if TYPE_CHECKING:
    import redis.asyncio as aioredis

    from dependencies.auth import CurrentUser

log = get_logger(__name__)


class CustomDomainService:
    """Orchestrator for the custom-domain feature."""

    def __init__(
        self,
        repo: CustomDomainRepository,
        verifiers: dict[VerificationMethod, DomainVerifier],
        edge_provisioner: EdgeProvisioner,
        registrar: HostnameRegistrar,
        settings: CustomDomainSettings,
        tenant_resolver: TenantResolver | None = None,
        blocked_domain_repo: BlockedDomainRepository | None = None,
        redis_client: aioredis.Redis | None = None,
    ) -> None:
        self._repo = repo
        self._verifiers = verifiers
        self._edge = edge_provisioner
        self._registrar = registrar
        self._settings = settings
        # Optional so unit tests can wire just the bits they care about.
        # Wiring (`dependencies/wiring.py`) always passes both so the
        # production path gets cache invalidation + blocklist checks.
        self._tenant_resolver = tenant_resolver
        self._blocked_repo = blocked_domain_repo
        self._redis = redis_client

    # ── Public API ───────────────────────────────────────────────────

    async def create(
        self,
        request: CreateCustomDomainRequest,
        user: CurrentUser,
    ) -> CustomDomainDoc:
        """Register a new custom domain. Doc is born in PENDING state."""
        self._require_enabled()

        await self._enforce_blocklist(request.fqdn)
        await self._enforce_uniqueness(request.fqdn)
        await self._enforce_per_user_quota(user.user_id)
        await self._enforce_create_attempts_quota(user.user_id)

        method = request.verification_method
        if method not in self._verifiers:
            # Defensive — DTO validator already rejects SYSTEM and unknown
            # methods. Hitting this branch implies a wiring bug.
            raise InvalidDomainTransitionError(
                f"unsupported verification method: {method.value}"
            )

        now = datetime.now(timezone.utc)
        doc = CustomDomainDoc(
            fqdn=request.fqdn,
            owner_id=user.user_id,
            status=DomainStatus.PENDING,
            verification_method=method,
            # Stamp a TXT token unconditionally — cheap, and lets the user
            # switch verification methods later without re-registering.
            verification_token=str(uuid.uuid4()),
            is_system_default=False,
            created_at=now,
        )
        try:
            new_id = await self._repo.insert(doc.to_mongo())
        except DuplicateKeyError:
            # Race lost — another request inserted the same fqdn between
            # our precheck and our insert. Translate to the same friendly
            # error the precheck would have raised so the API stays at 409
            # instead of leaking a 500 with a raw Mongo error.
            raise DomainAlreadyRegisteredError(
                f"domain {request.fqdn!r} is already registered"
            ) from None

        # Announce to the edge backend (CF SaaS = create custom hostname;
        # NoOp on self-host). On failure, roll back the Mongo insert so
        # the user can retry — leaving an orphan doc would block re-create
        # via the unique fqdn index.
        try:
            registration = await self._registrar.register(
                request.fqdn, dcv_method=method.value
            )
        except Exception as exc:
            try:
                await self._repo.delete_by_id(new_id)
            except Exception as rollback_exc:
                # Rollback failure leaves an orphan PENDING doc that blocks
                # re-create. Log loud so an operator can clean up via
                # mongosh; still raise the original error to the user.
                log.exception(
                    "audit.domain.registration_rollback_failed",
                    fqdn=request.fqdn,
                    domain_id=str(new_id),
                    owner_id=str(user.user_id),
                    rollback_error=str(rollback_exc),
                )
            log.warning(
                "audit.domain.registration_failed",
                fqdn=request.fqdn,
                domain_id=str(new_id),
                owner_id=str(user.user_id),
                verification_method=method.value,
                error=str(exc),
            )
            raise

        if (
            registration.backend_id is not None
            or registration.backend_metadata
            or registration.instructions
        ):
            await self._repo.update_edge_metadata(
                new_id,
                cf_hostname_id=registration.backend_id,
                cf_status=registration.backend_metadata.get("cf_status"),
                cf_ssl_status=registration.backend_metadata.get("cf_ssl_status"),
                dns_instructions=registration.instructions or None,
            )

        log.info(
            "audit.domain.created",
            fqdn=request.fqdn,
            domain_id=str(new_id),
            owner_id=str(user.user_id),
            verification_method=method.value,
        )

        # Re-fetch so the returned doc carries the canonical _id and any
        # server-side defaults (matches the repo contract elsewhere).
        created = await self._repo.find_by_id(new_id)
        if created is None:  # pragma: no cover — write succeeded above
            raise NotFoundError(f"domain {new_id} vanished after insert")
        return created

    async def verify(
        self,
        domain_id: ObjectId,
        user: CurrentUser,
    ) -> CustomDomainDoc:
        """Run the verifier strategy associated with this domain.

        On success, transitions to ACTIVE. On failure, stays in PENDING (or
        whatever non-terminal state) and records the error reason.
        """
        self._require_enabled()

        doc = await self._load_owned(domain_id, user)
        await self._enforce_verify_attempts_quota(domain_id)

        verifier = self._verifiers.get(doc.verification_method)
        if verifier is None:
            raise InvalidDomainTransitionError(
                f"no verifier wired for {doc.verification_method.value}"
            )

        result: VerificationResult = await verifier.verify(
            doc.fqdn, self._verifier_token(doc)
        )

        if result.verified:
            await self._transition(
                doc,
                DomainStatus.ACTIVE,
                last_verification_error=None,
                bump_last_verified_at=True,
            )
            # Drop any negative cache entry so the freshly-active domain
            # resolves on the very next request.
            await self._invalidate_cache(doc.fqdn)
            log.info(
                "audit.domain.verified",
                fqdn=doc.fqdn,
                domain_id=str(doc.id),
                owner_id=str(user.user_id),
                method=doc.verification_method.value,
                last_verification_error=None,
            )
        else:
            # Stay in current state; just record the latest reason so the
            # user can debug.  Do NOT auto-suspend on a single user-driven
            # verify — that's the worker's job after N consecutive fails.
            await self._repo.update_status(
                doc.id,
                doc.status,
                last_verification_error=result.reason,
            )
            log.info(
                "audit.domain.verified",
                fqdn=doc.fqdn,
                domain_id=str(doc.id),
                owner_id=str(user.user_id),
                method=doc.verification_method.value,
                last_verification_error=result.reason,
            )

        refreshed = await self._repo.find_by_id(doc.id)
        if refreshed is None:  # pragma: no cover
            raise NotFoundError(f"domain {doc.id} vanished after verify")
        return refreshed

    async def list_by_owner(
        self,
        user: CurrentUser,
        query: ListCustomDomainsQuery,
    ) -> tuple[list[CustomDomainDoc], int]:
        """Return (page, total_count) for the caller's domains."""
        # Read path is allowed even when the feature flag is off so existing
        # owners can see their domains during a rollback. Mutations remain
        # gated by ``_require_enabled``.
        skip = (query.page - 1) * query.page_size
        items = await self._repo.list_by_owner(
            user.user_id, skip=skip, limit=query.page_size
        )
        total = await self._repo.count_by_owner(user.user_id)
        return items, total

    async def delete(
        self,
        domain_id: ObjectId,
        user: CurrentUser,
    ) -> None:
        """Revoke a custom domain. REVOKED is terminal."""
        self._require_enabled()

        doc = await self._load_owned(domain_id, user)
        await self._transition(doc, DomainStatus.REVOKED)
        await self._announce_eviction(doc, kind="revoked")
        # Drop any positive cache entry so the now-revoked host stops
        # resolving immediately, not after the positive TTL window.
        await self._invalidate_cache(doc.fqdn)

        log.info(
            "audit.domain.revoked",
            fqdn=doc.fqdn,
            domain_id=str(doc.id),
            owner_id=str(user.user_id),
        )

    async def is_allowed_for_caddy(self, fqdn: str) -> bool:
        """Caddy ask endpoint authorisation check.

        Returns False unconditionally in PR2 — the route that consumes this
        ships in PR3 along with the Caddyfile changes that activate
        on-demand TLS. Default-deny matches the security model: even if the
        endpoint is reached early, no certs are minted.
        """
        return False

    # ── Background-worker helpers (used by PR5's reverify loop) ──────

    async def reverify_active(
        self, batch_size: int | None = None
    ) -> list[tuple[CustomDomainDoc, VerificationResult]]:
        """Re-check ACTIVE domains older than the configured freshness window.

        The actual ACTIVE→SUSPENDED suspension after N consecutive fails
        lives in the worker (PR5) so the consecutive-failure counter stays
        process-local. Here we only run the check + record latest result.
        """
        cutoff = datetime.now(timezone.utc) - timedelta(
            seconds=self._settings.max_verify_age_seconds
        )
        limit = batch_size or self._settings.reverify_batch_size
        stale = await self._repo.find_stale_active(cutoff, limit)

        out: list[tuple[CustomDomainDoc, VerificationResult]] = []
        for doc in stale:
            verifier = self._verifiers.get(doc.verification_method)
            if verifier is None:
                continue
            result = await verifier.verify(doc.fqdn, self._verifier_token(doc))
            if result.verified:
                await self._repo.update_status(
                    doc.id,
                    DomainStatus.ACTIVE,
                    last_verification_error=None,
                    bump_last_verified_at=True,
                )
            else:
                await self._repo.update_status(
                    doc.id,
                    doc.status,
                    last_verification_error=result.reason,
                )
            out.append((doc, result))
        return out

    async def suspend(
        self, domain_id: ObjectId, reason: str, *, actor: str = "worker"
    ) -> None:
        """Force a domain into SUSPENDED. Used by the reverify worker."""
        doc = await self._repo.find_by_id(domain_id)
        if doc is None:
            return
        await self._transition(
            doc,
            DomainStatus.SUSPENDED,
            last_verification_error=reason,
        )
        await self._announce_eviction(doc, kind="suspended")
        await self._invalidate_cache(doc.fqdn)
        log.info(
            "audit.domain.suspended",
            fqdn=doc.fqdn,
            domain_id=str(doc.id),
            owner_id=str(doc.owner_id),
            reason=reason,
            suspending_actor=actor,
        )

    # ── Internal: state machine, quotas, blocklist, cache ────────────

    @staticmethod
    def _verifier_token(doc: CustomDomainDoc) -> str | None:
        """Backend handle to feed into ``DomainVerifier.verify``.

        CF SaaS verifiers poll Cloudflare keyed on the CF hostname id;
        DNS verifiers (CNAME / A / TXT) only need the per-domain UUID
        token. Keeping the protocol signature uniform across backends
        means the service picks the right value here, not the verifier.
        Detection by enum value prefix so a future ``cf_*`` method auto-
        routes to ``cf_hostname_id`` without touching this branch.
        """
        if doc.verification_method.value.startswith("cf_"):
            return doc.cf_hostname_id
        return doc.verification_token

    def _require_enabled(self) -> None:
        if not self._settings.enabled:
            raise DomainQuotaExceededError("custom domains are not currently enabled")

    async def _invalidate_cache(self, fqdn: str) -> None:
        """Best-effort cache eviction for *fqdn*.

        Tolerates a missing resolver (unit tests that don't wire one) and
        any backend failure — staleness is degraded UX, not data loss.
        """
        if self._tenant_resolver is None:
            return
        try:
            await self._tenant_resolver.invalidate(fqdn)
        except Exception as exc:
            log.warning(
                "tenant_cache_invalidate_failed",
                fqdn=fqdn,
                error=str(exc),
            )

    async def _announce_eviction(self, doc: CustomDomainDoc, *, kind: str) -> None:
        """Tell the edge to drop *doc.fqdn* and persist the outcome.

        ``kind`` ("revoked" / "suspended") only affects the persisted error
        message — the edge call itself is the same for both. The PR5
        reverify worker scans for ``eviction_pending=True`` and retries.
        """
        ok = await self._edge.announce_revoked(doc.fqdn)
        await self._repo.set_eviction_pending(
            doc.id,
            pending=not ok,
            error=None if ok else f"caddy {kind} eviction failed",
        )

    async def _load_owned(
        self, domain_id: ObjectId, user: CurrentUser
    ) -> CustomDomainDoc:
        doc = await self._repo.find_by_id(domain_id)
        if doc is None:
            raise NotFoundError(f"domain {domain_id} not found")
        if doc.owner_id != user.user_id:
            raise ForbiddenError("you do not own this domain")
        return doc

    async def _transition(
        self,
        doc: CustomDomainDoc,
        new_status: DomainStatus,
        *,
        last_verification_error: str | None = None,
        bump_last_verified_at: bool = False,
    ) -> None:
        # Idempotency: self-loops are absent from LEGAL_TRANSITIONS by
        # design, but retrying verify/delete must not raise. Skip the
        # legality check; still bump timestamps + record latest error.
        if doc.status == new_status:
            await self._repo.update_status(
                doc.id,
                new_status,
                last_verification_error=last_verification_error,
                bump_last_verified_at=bump_last_verified_at,
            )
            return
        legal = LEGAL_TRANSITIONS.get(doc.status, frozenset())
        if new_status not in legal:
            raise InvalidDomainTransitionError(
                f"illegal transition {doc.status.value} -> {new_status.value}"
            )
        await self._repo.update_status(
            doc.id,
            new_status,
            last_verification_error=last_verification_error,
            bump_last_verified_at=bump_last_verified_at,
        )

    async def _enforce_uniqueness(self, fqdn: str) -> None:
        existing = await self._repo.find_by_fqdn(fqdn)
        if existing is not None:
            raise DomainAlreadyRegisteredError(f"domain {fqdn!r} is already registered")

    async def _enforce_per_user_quota(self, owner_id: ObjectId) -> None:
        current = await self._repo.count_by_owner(owner_id)
        if current >= self._settings.max_per_user:
            raise DomainQuotaExceededError(
                f"max custom domains per user reached ({self._settings.max_per_user})"
            )

    async def _enforce_create_attempts_quota(self, owner_id: ObjectId) -> None:
        # Per-day per-user counter — fails open when Redis is unavailable
        # (self-hosters without Redis don't get this protection but the
        # core quota above still bounds total domains).
        if self._redis is None:
            return
        key = f"domain_create_attempts:{owner_id}"
        try:
            count = await self._redis.incr(key)
            if count == 1:
                await self._redis.expire(key, 24 * 3600)
        except Exception as exc:
            log.warning("create_quota_redis_error", error=str(exc))
            return
        if count > self._settings.create_attempts_per_day:
            raise DomainQuotaExceededError("too many domain create attempts today")

    async def _enforce_verify_attempts_quota(self, domain_id: ObjectId) -> None:
        if self._redis is None:
            return
        key = f"domain_verify_attempts:{domain_id}"
        try:
            count = await self._redis.incr(key)
            if count == 1:
                await self._redis.expire(key, 3600)
        except Exception as exc:
            log.warning("verify_quota_redis_error", error=str(exc))
            return
        if count > self._settings.verify_attempts_per_hour:
            raise DomainQuotaExceededError("too many verification attempts this hour")

    async def _enforce_blocklist(self, fqdn: str) -> None:
        # Live Mongo lookup — no per-process cache so an operator can add an
        # abuse domain via mongosh and have the next create() honour it
        # without an app restart.
        if self._blocked_repo is None:
            return
        if await self._blocked_repo.is_blocked(fqdn):
            raise DomainBlocklistedError(f"domain {fqdn!r} is on the blocklist")
