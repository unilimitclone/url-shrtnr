"""Unit tests for CustomDomainService."""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest
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
from schemas.dto.requests.custom_domain import (
    CreateCustomDomainRequest,
    ListCustomDomainsQuery,
)
from schemas.enums.domain_status import DomainStatus, VerificationMethod
from schemas.models.custom_domain import CustomDomainDoc
from services.custom_domain_service import CustomDomainService
from services.verifiers.protocol import VerificationResult

USER_OID = ObjectId("aaaaaaaaaaaaaaaaaaaaaaaa")
DOMAIN_OID = ObjectId("bbbbbbbbbbbbbbbbbbbbbbbb")


def _user(user_id=USER_OID):
    u = MagicMock()
    u.user_id = user_id
    u.email_verified = True
    return u


def _doc(
    fqdn="links.acme.com",
    status=DomainStatus.PENDING,
    method=VerificationMethod.CNAME,
    owner_id=USER_OID,
    domain_id=DOMAIN_OID,
):
    return CustomDomainDoc(
        id=domain_id,
        fqdn=fqdn,
        owner_id=owner_id,
        status=status,
        verification_method=method,
        verification_token="token-abc",
        created_at=datetime.now(timezone.utc),
    )


def _settings(**overrides):
    base = {"enabled": True}
    base.update(overrides)
    return CustomDomainSettings(**base)


def _build_service(
    *,
    enabled=True,
    repo=None,
    verifiers=None,
    edge=None,
    tenant_resolver=None,
    blocked_domain_repo=None,
    redis=None,
    extra_settings=None,
):
    repo = repo or AsyncMock()
    repo.insert = AsyncMock(return_value=DOMAIN_OID)
    repo.count_by_owner = AsyncMock(return_value=0)
    repo.find_by_fqdn = AsyncMock(return_value=None)
    repo.find_by_id = AsyncMock(return_value=None)
    repo.update_status = AsyncMock(return_value=True)
    repo.set_eviction_pending = AsyncMock(return_value=True)

    if blocked_domain_repo is None:
        blocked_domain_repo = AsyncMock()
        # Default: nothing blocked.
        blocked_domain_repo.is_blocked = AsyncMock(return_value=False)

    if verifiers is None:
        cname = AsyncMock()
        cname.verify = AsyncMock(return_value=VerificationResult(True))
        a = AsyncMock()
        a.verify = AsyncMock(return_value=VerificationResult(True))
        txt = AsyncMock()
        txt.verify = AsyncMock(return_value=VerificationResult(True))
        verifiers = {
            VerificationMethod.CNAME: cname,
            VerificationMethod.A_RECORD: a,
            VerificationMethod.TXT_CHALLENGE: txt,
        }

    edge = edge or AsyncMock()
    # Default to "Caddy acked" so existing tests don't have to opt in.
    edge.announce_revoked = AsyncMock(return_value=True)
    tenant_resolver = tenant_resolver or AsyncMock()
    settings_kwargs = {"enabled": enabled, **(extra_settings or {})}
    settings = _settings(**settings_kwargs)
    return (
        CustomDomainService(
            repo=repo,
            verifiers=verifiers,
            edge_provisioner=edge,
            settings=settings,
            tenant_resolver=tenant_resolver,
            blocked_domain_repo=blocked_domain_repo,
            redis_client=redis,
        ),
        repo,
        verifiers,
        edge,
        tenant_resolver,
    )


class TestEnabledGate:
    @pytest.mark.asyncio
    async def test_create_refused_when_disabled(self):
        svc, _, _, _, _ = _build_service(enabled=False)
        req = CreateCustomDomainRequest(fqdn="links.acme.com")
        with pytest.raises(DomainQuotaExceededError):
            await svc.create(req, _user())

    @pytest.mark.asyncio
    async def test_verify_refused_when_disabled(self):
        svc, _, _, _, _ = _build_service(enabled=False)
        with pytest.raises(DomainQuotaExceededError):
            await svc.verify(DOMAIN_OID, _user())

    @pytest.mark.asyncio
    async def test_delete_refused_when_disabled(self):
        svc, _, _, _, _ = _build_service(enabled=False)
        with pytest.raises(DomainQuotaExceededError):
            await svc.delete(DOMAIN_OID, _user())

    @pytest.mark.asyncio
    async def test_list_allowed_when_disabled_for_rollback_visibility(self):
        # Reads stay open even when the master switch is off so existing
        # owners don't lose visibility into their domains during rollback.
        svc, repo, _, _, _ = _build_service(enabled=False)
        repo.list_by_owner = AsyncMock(return_value=[])
        repo.count_by_owner = AsyncMock(return_value=0)
        items, total = await svc.list_by_owner(_user(), ListCustomDomainsQuery())
        assert items == []
        assert total == 0

    @pytest.mark.asyncio
    async def test_is_allowed_for_caddy_returns_false_in_pr2(self):
        # Default-deny on the cert ask endpoint; PR3 wires up the real check.
        svc, _, _, _, _ = _build_service(enabled=True)
        assert await svc.is_allowed_for_caddy("anything.example.com") is False


class TestCreate:
    @pytest.mark.asyncio
    async def test_creates_pending_doc_with_token(self):
        svc, repo, _, _, _ = _build_service()
        repo.find_by_id = AsyncMock(return_value=_doc(status=DomainStatus.PENDING))
        req = CreateCustomDomainRequest(
            fqdn="links.acme.com", verification_method=VerificationMethod.TXT_CHALLENGE
        )
        doc = await svc.create(req, _user())
        assert doc.status == DomainStatus.PENDING
        repo.insert.assert_awaited_once()
        # Token should be stamped regardless of method.
        inserted = repo.insert.call_args.args[0]
        assert inserted["verification_token"] is not None

    @pytest.mark.asyncio
    async def test_uniqueness_conflict_raises(self):
        svc, repo, _, _, _ = _build_service()
        repo.find_by_fqdn = AsyncMock(return_value=_doc())
        req = CreateCustomDomainRequest(fqdn="links.acme.com")
        with pytest.raises(DomainAlreadyRegisteredError):
            await svc.create(req, _user())

    @pytest.mark.asyncio
    async def test_per_user_quota_enforced(self):
        svc, repo, _, _, _ = _build_service()
        repo.count_by_owner = AsyncMock(return_value=2)  # at default cap
        req = CreateCustomDomainRequest(fqdn="links.acme.com")
        with pytest.raises(DomainQuotaExceededError):
            await svc.create(req, _user())

    @pytest.mark.asyncio
    async def test_blocklist_enforced_via_repo(self):
        blocked = AsyncMock()
        blocked.is_blocked = AsyncMock(return_value=True)
        svc, _, _, _, _ = _build_service(blocked_domain_repo=blocked)
        req = CreateCustomDomainRequest(fqdn="evil.com")
        with pytest.raises(DomainBlocklistedError):
            await svc.create(req, _user())
        blocked.is_blocked.assert_awaited_once_with("evil.com")

    @pytest.mark.asyncio
    async def test_blocklist_skipped_when_repo_missing(self):
        # Service must tolerate a None blocked_domain_repo (unit tests
        # that don't wire it) without crashing.
        svc, repo, _, _, _ = _build_service(blocked_domain_repo=None)
        # Wiring sets it; bypass for the test.
        svc._blocked_repo = None
        repo.find_by_id = AsyncMock(return_value=_doc(status=DomainStatus.PENDING))
        req = CreateCustomDomainRequest(fqdn="anything.example.com")
        # Must not raise — just skip the check.
        await svc.create(req, _user())

    @pytest.mark.asyncio
    async def test_create_attempts_quota_via_redis(self):
        redis = AsyncMock()
        redis.incr = AsyncMock(return_value=99)  # way over cap of 3
        redis.expire = AsyncMock()
        svc, _, _, _, _ = _build_service(redis=redis)
        req = CreateCustomDomainRequest(fqdn="links.acme.com")
        with pytest.raises(DomainQuotaExceededError):
            await svc.create(req, _user())

    @pytest.mark.asyncio
    async def test_duplicate_key_during_race_translates_to_friendly_error(self):
        # Precheck passes (no existing doc) but the unique-index backstop
        # catches a concurrent insert. Service must translate to the same
        # 409-friendly error instead of leaking a 500 with raw Mongo text.
        svc, repo, _, _, _ = _build_service()
        repo.find_by_fqdn = AsyncMock(return_value=None)
        repo.insert = AsyncMock(
            side_effect=DuplicateKeyError("E11000 duplicate key error: fqdn")
        )
        req = CreateCustomDomainRequest(fqdn="links.acme.com")
        with pytest.raises(DomainAlreadyRegisteredError):
            await svc.create(req, _user())


class TestVerify:
    @pytest.mark.asyncio
    async def test_success_transitions_to_active(self):
        svc, repo, _, _, _ = _build_service()
        starting = _doc(status=DomainStatus.PENDING)
        # find_by_id called twice: load_owned + refresh
        repo.find_by_id = AsyncMock(
            side_effect=[starting, _doc(status=DomainStatus.ACTIVE)]
        )
        await svc.verify(DOMAIN_OID, _user())
        # update_status called with ACTIVE + bump_last_verified_at=True
        repo.update_status.assert_awaited()
        args, kwargs = repo.update_status.call_args
        assert args[1] == DomainStatus.ACTIVE
        assert kwargs["bump_last_verified_at"] is True
        assert kwargs["last_verification_error"] is None

    @pytest.mark.asyncio
    async def test_failure_records_reason_keeps_status(self):
        svc, repo, verifiers, _, _ = _build_service()
        verifiers[VerificationMethod.CNAME].verify = AsyncMock(
            return_value=VerificationResult(False, reason="DNS NXDOMAIN")
        )
        starting = _doc(status=DomainStatus.PENDING)
        repo.find_by_id = AsyncMock(side_effect=[starting, starting])
        await svc.verify(DOMAIN_OID, _user())
        args, kwargs = repo.update_status.call_args
        # Stays in PENDING — never auto-suspends on a single user-driven verify.
        assert args[1] == DomainStatus.PENDING
        assert kwargs["last_verification_error"] == "DNS NXDOMAIN"

    @pytest.mark.asyncio
    async def test_verify_on_already_active_is_idempotent(self):
        # Idempotency: re-clicking "Verify" on an ACTIVE domain (e.g. after
        # a transient browser network blip) must not raise. ACTIVE→ACTIVE
        # is deliberately omitted from LEGAL_TRANSITIONS — _transition()
        # short-circuits self-loops to a plain update_status so the call
        # still bumps last_verified_at without going through the legality
        # check.
        svc, repo, _, _, _ = _build_service()
        active = _doc(status=DomainStatus.ACTIVE)
        repo.find_by_id = AsyncMock(side_effect=[active, active])
        await svc.verify(DOMAIN_OID, _user())
        args, kwargs = repo.update_status.call_args
        assert args[1] == DomainStatus.ACTIVE
        assert kwargs["bump_last_verified_at"] is True

    @pytest.mark.asyncio
    async def test_not_owner_forbidden(self):
        svc, repo, _, _, _ = _build_service()
        someone_else = ObjectId()
        repo.find_by_id = AsyncMock(return_value=_doc(owner_id=someone_else))
        with pytest.raises(ForbiddenError):
            await svc.verify(DOMAIN_OID, _user())

    @pytest.mark.asyncio
    async def test_not_found_raises(self):
        svc, repo, _, _, _ = _build_service()
        repo.find_by_id = AsyncMock(return_value=None)
        with pytest.raises(NotFoundError):
            await svc.verify(DOMAIN_OID, _user())


class TestDelete:
    @pytest.mark.asyncio
    async def test_revokes_and_announces(self):
        svc, repo, _, edge, _ = _build_service()
        repo.find_by_id = AsyncMock(return_value=_doc(status=DomainStatus.ACTIVE))
        await svc.delete(DOMAIN_OID, _user())
        # update_status to REVOKED + edge.announce_revoked called
        args, _ = repo.update_status.call_args
        assert args[1] == DomainStatus.REVOKED
        edge.announce_revoked.assert_awaited_once_with("links.acme.com")

    @pytest.mark.asyncio
    async def test_delete_on_already_revoked_is_idempotent(self):
        # Idempotency: retrying delete() on a REVOKED domain must not raise.
        # LEGAL_TRANSITIONS[REVOKED] is empty (terminal), so without the
        # self-loop short-circuit in _transition() this would raise
        # InvalidDomainTransitionError on every retry — bad UX for a user
        # who refreshes the dashboard or hits a transient network error
        # mid-delete.
        svc, repo, _, edge, _ = _build_service()
        repo.find_by_id = AsyncMock(return_value=_doc(status=DomainStatus.REVOKED))
        await svc.delete(DOMAIN_OID, _user())
        # update_status still called (records timestamps); status unchanged.
        args, _ = repo.update_status.call_args
        assert args[1] == DomainStatus.REVOKED
        edge.announce_revoked.assert_awaited_once()


class TestSuspend:
    @pytest.mark.asyncio
    async def test_active_to_suspended_legal(self):
        svc, repo, _, edge, _ = _build_service()
        repo.find_by_id = AsyncMock(return_value=_doc(status=DomainStatus.ACTIVE))
        await svc.suspend(DOMAIN_OID, reason="3 consecutive fails")
        args, _ = repo.update_status.call_args
        assert args[1] == DomainStatus.SUSPENDED
        edge.announce_revoked.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_pending_to_suspended_illegal(self):
        # PENDING → SUSPENDED isn't in LEGAL_TRANSITIONS; should raise.
        svc, repo, _, _, _ = _build_service()
        repo.find_by_id = AsyncMock(return_value=_doc(status=DomainStatus.PENDING))
        with pytest.raises(InvalidDomainTransitionError):
            await svc.suspend(DOMAIN_OID, reason="test")


class TestCacheInvalidation:
    """Every state transition must invalidate the tenant resolver cache so
    the new state is visible to the next request, not after the TTL window.
    """

    @pytest.mark.asyncio
    async def test_verify_success_invalidates_negative_cache(self):
        svc, repo, _, _, resolver = _build_service()
        repo.find_by_id = AsyncMock(
            side_effect=[
                _doc(status=DomainStatus.PENDING),
                _doc(status=DomainStatus.ACTIVE),
            ]
        )
        await svc.verify(DOMAIN_OID, _user())
        resolver.invalidate.assert_awaited_once_with("links.acme.com")

    @pytest.mark.asyncio
    async def test_verify_failure_does_not_invalidate(self):
        svc, repo, verifiers, _, resolver = _build_service()
        verifiers[VerificationMethod.CNAME].verify = AsyncMock(
            return_value=VerificationResult(False, reason="DNS NXDOMAIN")
        )
        starting = _doc(status=DomainStatus.PENDING)
        repo.find_by_id = AsyncMock(side_effect=[starting, starting])
        await svc.verify(DOMAIN_OID, _user())
        # Status didn't change → no cache to drop.
        resolver.invalidate.assert_not_called()

    @pytest.mark.asyncio
    async def test_delete_invalidates_cache(self):
        svc, repo, _, _, resolver = _build_service()
        repo.find_by_id = AsyncMock(return_value=_doc(status=DomainStatus.ACTIVE))
        await svc.delete(DOMAIN_OID, _user())
        resolver.invalidate.assert_awaited_once_with("links.acme.com")

    @pytest.mark.asyncio
    async def test_suspend_invalidates_cache(self):
        svc, repo, _, _, resolver = _build_service()
        repo.find_by_id = AsyncMock(return_value=_doc(status=DomainStatus.ACTIVE))
        await svc.suspend(DOMAIN_OID, reason="test")
        resolver.invalidate.assert_awaited_once_with("links.acme.com")


class TestEvictionTracking:
    """Caddy revocation outcomes get persisted on the doc so the worker
    (PR5) can retry stale evictions. ``status`` and ``eviction_pending``
    are independent dimensions — both get updated, neither gates the other.
    """

    @pytest.mark.asyncio
    async def test_delete_with_caddy_ack_clears_eviction_pending(self):
        svc, repo, _, edge, _ = _build_service()
        edge.announce_revoked = AsyncMock(return_value=True)
        repo.find_by_id = AsyncMock(return_value=_doc(status=DomainStatus.ACTIVE))

        await svc.delete(DOMAIN_OID, _user())

        repo.set_eviction_pending.assert_awaited_once()
        kwargs = repo.set_eviction_pending.call_args.kwargs
        assert kwargs["pending"] is False
        assert kwargs["error"] is None

    @pytest.mark.asyncio
    async def test_delete_with_caddy_failure_marks_eviction_pending(self):
        svc, repo, _, edge, _ = _build_service()
        edge.announce_revoked = AsyncMock(return_value=False)
        repo.find_by_id = AsyncMock(return_value=_doc(status=DomainStatus.ACTIVE))

        await svc.delete(DOMAIN_OID, _user())

        kwargs = repo.set_eviction_pending.call_args.kwargs
        assert kwargs["pending"] is True
        assert "revoked" in kwargs["error"]

    @pytest.mark.asyncio
    async def test_suspend_with_caddy_failure_marks_eviction_pending(self):
        svc, repo, _, edge, _ = _build_service()
        edge.announce_revoked = AsyncMock(return_value=False)
        repo.find_by_id = AsyncMock(return_value=_doc(status=DomainStatus.ACTIVE))

        await svc.suspend(DOMAIN_OID, reason="test")

        kwargs = repo.set_eviction_pending.call_args.kwargs
        assert kwargs["pending"] is True
        assert "suspended" in kwargs["error"]

    @pytest.mark.asyncio
    async def test_status_transition_happens_regardless_of_caddy_outcome(self):
        # Even if Caddy fails, the status MUST move to REVOKED — the
        # in-app TenantResolver is the gating authority, not Caddy.
        svc, repo, _, edge, _ = _build_service()
        edge.announce_revoked = AsyncMock(return_value=False)
        repo.find_by_id = AsyncMock(return_value=_doc(status=DomainStatus.ACTIVE))

        await svc.delete(DOMAIN_OID, _user())

        # update_status was called with REVOKED first
        first_call = repo.update_status.call_args_list[0]
        assert first_call.args[1] == DomainStatus.REVOKED


class TestSuspendNotFound:
    @pytest.mark.asyncio
    async def test_suspend_missing_domain_is_noop(self):
        # Worker may race with a concurrent delete — domain disappears
        # between scan and suspend. Must silently noop, not crash.
        svc, repo, _, edge, _ = _build_service()
        repo.find_by_id = AsyncMock(return_value=None)

        # Must not raise
        await svc.suspend(DOMAIN_OID, reason="missing_domain_ok")

        repo.update_status.assert_not_called()
        edge.announce_revoked.assert_not_called()


class TestVerifyAttemptsQuota:
    @pytest.mark.asyncio
    async def test_quota_increments_redis_counter(self):
        redis = AsyncMock()
        redis.incr = AsyncMock(return_value=1)
        redis.expire = AsyncMock()
        svc, repo, _, _, _ = _build_service(redis=redis)
        starting = _doc(status=DomainStatus.PENDING)
        repo.find_by_id = AsyncMock(side_effect=[starting, starting])

        await svc.verify(DOMAIN_OID, _user())

        redis.incr.assert_awaited_once()
        # First incr → expire is set so the counter rolls over after the window
        redis.expire.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_quota_exceeded_raises_quota_error(self):
        redis = AsyncMock()
        redis.incr = AsyncMock(return_value=99)  # well over default cap of 5
        redis.expire = AsyncMock()
        svc, repo, _, _, _ = _build_service(redis=redis)
        repo.find_by_id = AsyncMock(return_value=_doc(status=DomainStatus.PENDING))

        with pytest.raises(DomainQuotaExceededError):
            await svc.verify(DOMAIN_OID, _user())

    @pytest.mark.asyncio
    async def test_quota_fails_open_when_redis_errors(self):
        # If Redis is down we degrade to "no quota enforcement" rather than
        # blocking all verifies — staff allowlist + per-user-per-domain
        # natural rate-limit cover the abuse vector.
        redis = AsyncMock()
        redis.incr = AsyncMock(side_effect=Exception("redis down"))
        svc, repo, _, _, _ = _build_service(redis=redis)
        starting = _doc(status=DomainStatus.PENDING)
        repo.find_by_id = AsyncMock(side_effect=[starting, starting])

        # Must not raise — verify proceeds normally despite Redis fault.
        await svc.verify(DOMAIN_OID, _user())


class TestReverifyActive:
    @pytest.mark.asyncio
    async def test_success_bumps_last_verified_and_clears_error(self):
        svc, repo, _, _, _ = _build_service()
        d = _doc(status=DomainStatus.ACTIVE)
        repo.find_stale_active = AsyncMock(return_value=[d])

        result_pairs = await svc.reverify_active(batch_size=10)

        assert len(result_pairs) == 1
        ok_call = repo.update_status.call_args
        # ACTIVE remains, last_verified_at bumped, error cleared
        assert ok_call.args[1] == DomainStatus.ACTIVE
        assert ok_call.kwargs["bump_last_verified_at"] is True
        assert ok_call.kwargs["last_verification_error"] is None

    @pytest.mark.asyncio
    async def test_failure_records_reason_keeps_status(self):
        svc, repo, verifiers, _, _ = _build_service()
        verifiers[VerificationMethod.CNAME].verify = AsyncMock(
            return_value=VerificationResult(False, reason="DNS NXDOMAIN")
        )
        d = _doc(status=DomainStatus.ACTIVE)
        repo.find_stale_active = AsyncMock(return_value=[d])

        await svc.reverify_active(batch_size=10)

        # Status unchanged (worker doesn't auto-suspend on a single fail —
        # that's the consecutive-failure counter's job, lives in the worker)
        call = repo.update_status.call_args
        assert call.args[1] == DomainStatus.ACTIVE
        # bump_last_verified_at omitted on failure → default False applies.
        assert call.kwargs.get("bump_last_verified_at", False) is False
        assert call.kwargs["last_verification_error"] == "DNS NXDOMAIN"

    @pytest.mark.asyncio
    async def test_skips_doc_when_verifier_missing(self):
        # Defensive: if a doc references a verification_method that isn't
        # wired (legacy data), the loop must skip it without crashing.
        svc, repo, _, _, _ = _build_service(verifiers={})  # no verifiers
        d = _doc(status=DomainStatus.ACTIVE)
        repo.find_stale_active = AsyncMock(return_value=[d])

        result_pairs = await svc.reverify_active(batch_size=10)

        assert result_pairs == []
        repo.update_status.assert_not_called()
