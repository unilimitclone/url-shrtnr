"""Unit tests for CustomDomainService."""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest
from bson import ObjectId

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
    redis=None,
    extra_settings=None,
):
    repo = repo or AsyncMock()
    repo.insert = AsyncMock(return_value=DOMAIN_OID)
    repo.count_by_owner = AsyncMock(return_value=0)
    repo.find_by_fqdn = AsyncMock(return_value=None)
    repo.find_by_id = AsyncMock(return_value=None)
    repo.update_status = AsyncMock(return_value=True)

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
    async def test_blocklist_enforced(self, tmp_path):
        blockfile = tmp_path / "block.txt"
        blockfile.write_text("links.acme.com\nevil.com\n# comment line\n")
        svc, _, _, _, _ = _build_service(
            extra_settings={"blocklist_path": str(blockfile)}
        )
        req = CreateCustomDomainRequest(fqdn="links.acme.com")
        with pytest.raises(DomainBlocklistedError):
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
    async def test_revoked_to_active_illegal(self):
        # State machine guard — REVOKED is terminal; can't transition to ACTIVE.
        svc, repo, _, _, _ = _build_service()
        repo.find_by_id = AsyncMock(return_value=_doc(status=DomainStatus.REVOKED))
        with pytest.raises(InvalidDomainTransitionError):
            await svc.delete(
                DOMAIN_OID, _user()
            )  # any transition out of REVOKED illegal


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
