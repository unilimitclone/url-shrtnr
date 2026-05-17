"""Custom-domain lifecycle orchestrator. Owns state machine, quotas, and
audit.domain.* events. Mutations gated by settings.enabled."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

import tldextract
from bson import ObjectId
from pymongo.errors import DuplicateKeyError

from config import CustomDomainSettings
from errors import (
    DomainAlreadyRegisteredError,
    DomainBlocklistedError,
    DomainNotVerifiedError,
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
from services.dns_preflight import check_cname, uses_cloudflare_dns
from services.edge_provisioner.protocol import EdgeProvisioner
from services.registrar.protocol import HostnameRegistrar
from services.tenant_resolver.protocol import TenantResolver
from services.verifiers.protocol import DomainVerifier, VerificationResult

if TYPE_CHECKING:
    import redis.asyncio as aioredis

    from dependencies.auth import CurrentUser
    from services.url_service import UrlService

log = get_logger(__name__)

_tld_extractor = tldextract.TLDExtract(cache_dir=None)


def _is_apex(fqdn: str) -> bool:
    """True when the fqdn is the registrable apex (no subdomain). Uses the
    public suffix list via tldextract so multi-part TLDs like `co.uk` work."""
    ext = _tld_extractor(fqdn.strip("."))
    return bool(ext.domain) and bool(ext.suffix) and not ext.subdomain


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
        preflight_cname_target: str | None = None,
        url_service: UrlService | None = None,
    ) -> None:
        self._repo = repo
        self._verifiers = verifiers
        self._edge = edge_provisioner
        self._registrar = registrar
        self._settings = settings
        self._tenant_resolver = tenant_resolver
        self._blocked_repo = blocked_domain_repo
        self._redis = redis_client
        # None = preflight off (tests, self-host LE).
        self._preflight_cname_target = preflight_cname_target
        # None = cascade delete unavailable (tests). Production wiring sets this.
        self._url_service = url_service

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

        method = self._pick_verification_method(request.fqdn)
        if method not in self._verifiers:
            raise InvalidDomainTransitionError(
                f"unsupported verification method: {method.value}"
            )

        now = datetime.now(timezone.utc)
        setup_notes = await self._build_setup_notes(request.fqdn)
        doc = CustomDomainDoc(
            fqdn=request.fqdn,
            owner_id=user.user_id,
            status=DomainStatus.PENDING,
            verification_method=method,
            verification_token=str(uuid.uuid4()),
            is_system_default=False,
            created_at=now,
            setup_notes=setup_notes,
        )
        try:
            new_id = await self._repo.insert(doc.to_mongo())
        except DuplicateKeyError:
            # Race with concurrent insert — translate to 409 instead of 500.
            raise DomainAlreadyRegisteredError(
                f"domain {request.fqdn!r} is already registered"
            ) from None

        try:
            registration = await self._registrar.register(
                request.fqdn, dcv_method=method.value
            )
        except Exception as exc:
            # Roll back Mongo so a CF failure doesn't block re-create.
            try:
                await self._repo.delete_by_id(new_id)
            except Exception as rollback_exc:
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

        created = await self._repo.find_by_id(new_id)
        if created is None:  # pragma: no cover
            raise NotFoundError(f"domain {new_id} vanished after insert")
        return created

    async def verify(
        self,
        domain_id: ObjectId,
        user: CurrentUser,
    ) -> CustomDomainDoc:
        """Dispatch the verifier. Success → ACTIVE. Failure records reason."""
        self._require_enabled()

        doc = await self._load_owned(domain_id, user)
        await self._enforce_verify_attempts_quota(domain_id)

        # DNS preflight short-circuits CF API calls so unpropagated domains
        # don't trigger CF's 15-min backoff. Soft failure: recorded as
        # last_verification_error, not raised.
        if self._preflight_cname_target:
            preflight = await check_cname(doc.fqdn, self._preflight_cname_target)
            if not preflight.ok:
                await self._repo.update_status(
                    doc.id,
                    doc.status,
                    last_verification_error=preflight.reason,
                )
                log.info(
                    "audit.domain.preflight_failed",
                    fqdn=doc.fqdn,
                    domain_id=str(doc.id),
                    owner_id=str(user.user_id),
                    reason=preflight.reason,
                )
                refreshed = await self._repo.find_by_id(doc.id)
                return refreshed or doc

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
            # Stay in current state; record reason. No auto-suspend on a
            # single failed click — sync worker (PR5) owns that.
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
        """Return (page, total_count) for caller's domains. Reads bypass flag
        gate so owners can still see their state during a rollback."""
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
        *,
        cascade: bool = False,
    ) -> tuple[CustomDomainDoc, int]:
        """Revoke a custom domain. REVOKED is terminal.

        When ``cascade=True``, bulk-deletes all URLs owned by the user on the
        revoked fqdn. Returns ``(doc, urls_deleted)`` so callers can surface
        the deletion count.

        Order: transition to REVOKED FIRST so concurrent shortens can't sneak
        in. Then bulk delete (best-effort — partial failure leaves orphans
        for the PR5 GC worker). Then announce eviction + invalidate cache.
        """
        self._require_enabled()

        doc = await self._load_owned(domain_id, user)
        await self._transition(doc, DomainStatus.REVOKED)

        urls_deleted = 0
        if cascade:
            if self._url_service is None:
                log.error(
                    "audit.domain.cascade_unavailable",
                    fqdn=doc.fqdn,
                    domain_id=str(doc.id),
                )
            else:
                try:
                    urls_deleted = await self._url_service.delete_all_by_domain(
                        user.user_id, doc.fqdn
                    )
                except Exception as exc:
                    log.warning(
                        "audit.domain.cascade_partial",
                        fqdn=doc.fqdn,
                        domain_id=str(doc.id),
                        owner_id=str(user.user_id),
                        error=str(exc),
                    )

        await self._announce_eviction(doc, kind="revoked")
        await self._invalidate_cache(doc.fqdn)

        log.info(
            "audit.domain.revoked",
            fqdn=doc.fqdn,
            domain_id=str(doc.id),
            owner_id=str(user.user_id),
            cascade=cascade,
            urls_deleted=urls_deleted,
        )

        refreshed = await self._repo.find_by_id(doc.id)
        return refreshed or doc, urls_deleted

    async def assert_owned(
        self,
        user: CurrentUser,
        fqdn: str,
    ) -> CustomDomainDoc:
        """Find domain by fqdn, raise 403/404. No status check.

        Used by bulk URL delete which should work on revoked/suspended domains
        too (cleanup path)."""
        doc = await self._repo.find_by_fqdn(fqdn)
        if doc is None:
            raise NotFoundError(f"domain {fqdn!r} not found")
        if doc.owner_id != user.user_id:
            raise ForbiddenError("you do not own this domain")
        return doc

    async def assert_owned_and_active(
        self,
        user: CurrentUser,
        fqdn: str,
    ) -> CustomDomainDoc:
        """Find domain, assert ownership + ACTIVE. Used by shorten flow."""
        doc = await self.assert_owned(user, fqdn)
        if doc.status != DomainStatus.ACTIVE:
            raise DomainNotVerifiedError(
                f"domain {fqdn!r} is {doc.status.value}, not ACTIVE"
            )
        return doc

    async def is_allowed_for_caddy(self, fqdn: str) -> bool:
        """Caddy on-demand TLS ask endpoint. Default-deny; wired when the
        LE path ever ships routes for it."""
        return False

    # ── PR5 sync worker helpers ──────────────────────────────────────

    async def reverify_active(
        self, batch_size: int | None = None
    ) -> list[tuple[CustomDomainDoc, VerificationResult]]:
        """Re-check ACTIVE domains older than freshness window. Worker (PR5)
        handles ACTIVE→SUSPENDED on N consecutive fails."""
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

    def _pick_verification_method(self, fqdn: str) -> VerificationMethod:
        """Backend picks DCV method. CF SaaS → cf_http_dcv. Self-host LE →
        a_record for apex, cname otherwise."""
        if VerificationMethod.CF_HTTP_DCV in self._verifiers:
            return VerificationMethod.CF_HTTP_DCV
        if _is_apex(fqdn) and VerificationMethod.A_RECORD in self._verifiers:
            return VerificationMethod.A_RECORD
        return VerificationMethod.CNAME

    @staticmethod
    def _verifier_token(doc: CustomDomainDoc) -> str | None:
        # CF backends key off the cf_hostname_id; DNS verifiers off the
        # per-domain UUID. Prefix check auto-routes new cf_* methods.
        if doc.verification_method.value.startswith("cf_"):
            return doc.cf_hostname_id
        return doc.verification_token

    def _require_enabled(self) -> None:
        if not self._settings.enabled:
            raise DomainQuotaExceededError("custom domains are not currently enabled")

    async def _invalidate_cache(self, fqdn: str) -> None:
        """Best-effort tenant-cache eviction. Staleness is degraded UX, not data loss."""
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
        """Tell edge to drop fqdn. Stamps eviction_pending on failure for
        PR5 sync worker to retry. ``kind`` only affects the error message."""
        ok = await self._edge.announce_revoked(doc.fqdn)
        await self._repo.set_eviction_pending(
            doc.id,
            pending=not ok,
            error=None if ok else f"caddy {kind} eviction failed",
        )

    async def get_owned_by_id(
        self,
        domain_id: ObjectId,
        user: CurrentUser,
    ) -> CustomDomainDoc:
        """Public read for the caller's domain by id. 403/404 same as mutations.

        Used by the detail view, refresh-after-verify, and auto-poll. Bypasses
        the master `enabled` flag so owners can see their state during rollback.
        """
        return await self._load_owned(domain_id, user)

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
        # Self-loop = idempotent retry. Skip legality; still bump fields.
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
        # Fails open without Redis; per-user count still bounds totals.
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

    async def _build_setup_notes(self, fqdn: str) -> list[str]:
        # NS lookup is only meaningful on the CF SaaS path; grey-cloud is a
        # CF-SaaS-specific gotcha. Skip on self-host LE.
        if not self._preflight_cname_target:
            return []
        notes: list[str] = []
        try:
            if await uses_cloudflare_dns(fqdn):
                notes.append(
                    "Your domain uses Cloudflare DNS. Both DNS records must be "
                    "set to **DNS only** (grey cloud), not Proxied (orange cloud), "
                    "or CF SaaS validation will fail."
                )
        except Exception as exc:
            log.warning("setup_notes_ns_lookup_failed", fqdn=fqdn, error=str(exc))
        return notes

    async def _enforce_blocklist(self, fqdn: str) -> None:
        # Live Mongo — operator can add an abuse domain via mongosh and the
        # next create() honours it without restart.
        if self._blocked_repo is None:
            return
        if await self._blocked_repo.is_blocked(fqdn):
            raise DomainBlocklistedError(f"domain {fqdn!r} is on the blocklist")
