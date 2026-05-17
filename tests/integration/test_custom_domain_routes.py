"""Integration tests for custom-domain routes.

Covers happy + sad paths on:
    POST   /api/v1/custom-domains
    POST   /api/v1/custom-domains/{id}/verify
    GET    /api/v1/custom-domains
    DELETE /api/v1/custom-domains/{id}

Service is mocked. Tests pin contract: flag-gate behavior, scope auth,
response shape, cascade plumbing.
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock

from bson import ObjectId
from fastapi.testclient import TestClient

from dependencies import (
    CurrentUser,
    get_current_user,
    get_custom_domain_service,
    get_feature_flag_service,
)
from errors import (
    DomainAlreadyRegisteredError,
    ForbiddenError,
    NotFoundError,
)
from routes.api_v1 import router as api_v1_router
from schemas.enums.domain_status import DomainStatus, VerificationMethod
from schemas.models.custom_domain import CustomDomainDoc
from tests.conftest import build_test_app

_USER_ID = ObjectId()
_DOMAIN_ID = ObjectId()


def _user(verified: bool = True) -> CurrentUser:
    return CurrentUser(user_id=_USER_ID, email_verified=verified, api_key_doc=None)


def _doc(**overrides) -> CustomDomainDoc:
    base = {
        "_id": _DOMAIN_ID,
        "fqdn": "links.acme.com",
        "owner_id": _USER_ID,
        "status": DomainStatus.PENDING,
        "verification_method": VerificationMethod.CF_HTTP_DCV,
        "verification_token": "tok",
        "created_at": datetime(2025, 1, 1, tzinfo=timezone.utc),
        "dns_instructions": [
            {"type": "CNAME", "name": "links.acme.com", "value": "spoo.me"}
        ],
        "setup_notes": [],
    }
    base.update(overrides)
    return CustomDomainDoc.from_mongo(base)


def _flag_svc(enabled: bool = True):
    svc = AsyncMock()
    svc.is_enabled = AsyncMock(return_value=enabled)
    return svc


def _make_app(svc_mock, flag_enabled=True, current_user=None):
    """Wire test app, overriding get_current_user so the real auth dependency
    chain (require_auth → require_scopes → require_scopes_verified) executes
    against the stub user. Lets us exercise the scope and email-verified
    checks without re-mocking each layer."""
    user = current_user if current_user is not None else _user(verified=True)
    return build_test_app(
        api_v1_router,
        overrides={
            get_current_user: lambda: user,
            get_custom_domain_service: lambda: svc_mock,
            get_feature_flag_service: lambda: _flag_svc(flag_enabled),
        },
    )


class TestCreateCustomDomain:
    def test_happy_path(self):
        svc = AsyncMock()
        svc.create = AsyncMock(return_value=_doc())
        client = TestClient(_make_app(svc), raise_server_exceptions=False)

        resp = client.post("/api/v1/custom-domains", json={"fqdn": "links.acme.com"})

        assert resp.status_code == 201
        body = resp.json()
        assert body["fqdn"] == "links.acme.com"
        assert body["status"].lower() == "pending"
        assert body["dns_records"][0]["type"] == "CNAME"
        # Internal field NOT exposed.
        assert "verification_token" not in body
        assert "setup_instructions" not in body

    def test_flag_not_enabled_returns_404(self):
        svc = AsyncMock()
        svc.create = AsyncMock(return_value=_doc())
        client = TestClient(
            _make_app(svc, flag_enabled=False), raise_server_exceptions=False
        )

        resp = client.post("/api/v1/custom-domains", json={"fqdn": "links.acme.com"})
        assert resp.status_code == 404
        svc.create.assert_not_called()

    def test_unverified_email_returns_403(self):
        # Real require_scopes_verified chain fires: user is authed but
        # email_verified=False → EmailNotVerifiedError → 403.
        svc = AsyncMock()
        client = TestClient(
            _make_app(svc, current_user=_user(verified=False)),
            raise_server_exceptions=False,
        )
        resp = client.post("/api/v1/custom-domains", json={"fqdn": "links.acme.com"})
        assert resp.status_code == 403
        assert resp.json()["code"] == "EMAIL_NOT_VERIFIED"
        svc.create.assert_not_called()

    def test_unauthenticated_returns_401(self):
        # get_current_user → None triggers require_auth → 401.
        app = build_test_app(
            api_v1_router,
            overrides={
                get_current_user: lambda: None,
                get_custom_domain_service: lambda: AsyncMock(),
                get_feature_flag_service: lambda: _flag_svc(True),
            },
        )
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post("/api/v1/custom-domains", json={"fqdn": "links.acme.com"})
        assert resp.status_code == 401

    def test_duplicate_returns_409(self):
        svc = AsyncMock()
        svc.create = AsyncMock(
            side_effect=DomainAlreadyRegisteredError("already registered")
        )
        client = TestClient(_make_app(svc), raise_server_exceptions=False)
        resp = client.post("/api/v1/custom-domains", json={"fqdn": "links.acme.com"})
        assert resp.status_code == 409


class TestVerifyCustomDomain:
    def test_happy_path(self):
        svc = AsyncMock()
        svc.verify = AsyncMock(return_value=_doc(status=DomainStatus.ACTIVE))
        client = TestClient(_make_app(svc), raise_server_exceptions=False)
        resp = client.post(f"/api/v1/custom-domains/{_DOMAIN_ID}/verify", json={})
        assert resp.status_code == 200
        assert resp.json()["status"].lower() == "active"

    def test_not_owner_returns_403(self):
        svc = AsyncMock()
        svc.verify = AsyncMock(side_effect=ForbiddenError("not yours"))
        client = TestClient(_make_app(svc), raise_server_exceptions=False)
        resp = client.post(f"/api/v1/custom-domains/{_DOMAIN_ID}/verify", json={})
        assert resp.status_code == 403

    def test_invalid_id_returns_422(self):
        # Path pattern rejects bad ids before service is called.
        svc = AsyncMock()
        client = TestClient(_make_app(svc), raise_server_exceptions=False)
        resp = client.post("/api/v1/custom-domains/notanid/verify", json={})
        assert resp.status_code == 422
        svc.verify.assert_not_called()


class TestListCustomDomains:
    def test_paginated_response(self):
        svc = AsyncMock()
        svc.list_by_owner = AsyncMock(return_value=([_doc()], 1))
        client = TestClient(_make_app(svc), raise_server_exceptions=False)
        resp = client.get("/api/v1/custom-domains")
        assert resp.status_code == 200
        body = resp.json()
        assert body["total"] == 1
        assert body["pageSize"] == 20
        assert body["hasNext"] is False
        assert body["items"][0]["fqdn"] == "links.acme.com"

    def test_empty_list(self):
        svc = AsyncMock()
        svc.list_by_owner = AsyncMock(return_value=([], 0))
        client = TestClient(_make_app(svc), raise_server_exceptions=False)
        resp = client.get("/api/v1/custom-domains")
        assert resp.status_code == 200
        assert resp.json()["items"] == []

    def test_reads_bypass_flag(self):
        # Even with flag disabled, GET must succeed (rollback visibility).
        svc = AsyncMock()
        svc.list_by_owner = AsyncMock(return_value=([_doc()], 1))
        client = TestClient(
            _make_app(svc, flag_enabled=False), raise_server_exceptions=False
        )
        resp = client.get("/api/v1/custom-domains")
        assert resp.status_code == 200


class TestDeleteCustomDomain:
    def test_no_cascade_returns_zero(self):
        svc = AsyncMock()
        svc.delete = AsyncMock(return_value=(_doc(status=DomainStatus.REVOKED), 0))
        client = TestClient(_make_app(svc), raise_server_exceptions=False)
        resp = client.delete(f"/api/v1/custom-domains/{_DOMAIN_ID}")
        assert resp.status_code == 200
        body = resp.json()
        assert body["cascade"] is False
        assert body["urls_deleted"] == 0
        svc.delete.assert_awaited_once()
        assert svc.delete.call_args.kwargs["cascade"] is False

    def test_cascade_returns_count(self):
        svc = AsyncMock()
        svc.delete = AsyncMock(return_value=(_doc(status=DomainStatus.REVOKED), 42))
        client = TestClient(_make_app(svc), raise_server_exceptions=False)
        resp = client.delete(f"/api/v1/custom-domains/{_DOMAIN_ID}?cascade=true")
        assert resp.status_code == 200
        body = resp.json()
        assert body["cascade"] is True
        assert body["urls_deleted"] == 42
        assert svc.delete.call_args.kwargs["cascade"] is True

    def test_not_found_returns_404(self):
        svc = AsyncMock()
        svc.delete = AsyncMock(side_effect=NotFoundError("domain not found"))
        client = TestClient(_make_app(svc), raise_server_exceptions=False)
        resp = client.delete(f"/api/v1/custom-domains/{_DOMAIN_ID}")
        assert resp.status_code == 404

    def test_not_owner_returns_403(self):
        svc = AsyncMock()
        svc.delete = AsyncMock(side_effect=ForbiddenError("not yours"))
        client = TestClient(_make_app(svc), raise_server_exceptions=False)
        resp = client.delete(f"/api/v1/custom-domains/{_DOMAIN_ID}")
        assert resp.status_code == 403
