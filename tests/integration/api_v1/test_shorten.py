"""Tests for POST /api/v1/shorten."""

from __future__ import annotations

from unittest.mock import AsyncMock

from bson import ObjectId
from fastapi.testclient import TestClient

from dependencies import get_current_user, get_url_service
from errors import ConflictError, ValidationError

from .conftest import _build_test_app, _make_api_key_doc, _make_url_doc, _make_user


class TestShortenEmailVerification:
    """Unverified authenticated users must not be able to create URLs."""

    def test_shorten_unverified_email_returns_403(self):
        user = _make_user(email_verified=False)
        mock_svc = AsyncMock()

        application = _build_test_app(
            {get_current_user: lambda: user, get_url_service: lambda: mock_svc}
        )
        with TestClient(application, raise_server_exceptions=False) as client:
            resp = client.post(
                "/api/v1/shorten", json={"long_url": "https://example.com"}
            )

        assert resp.status_code == 403
        assert resp.json()["code"] == "EMAIL_NOT_VERIFIED"
        mock_svc.create.assert_not_called()

    def test_shorten_verified_email_returns_201(self):
        user = _make_user(email_verified=True)
        url_doc = _make_url_doc(owner_id=user.user_id)
        mock_svc = AsyncMock()
        mock_svc.create = AsyncMock(return_value=url_doc)

        application = _build_test_app(
            {get_current_user: lambda: user, get_url_service: lambda: mock_svc}
        )
        with TestClient(application, raise_server_exceptions=True) as client:
            resp = client.post(
                "/api/v1/shorten", json={"long_url": "https://example.com"}
            )

        assert resp.status_code == 201
        mock_svc.create.assert_called_once()


class TestShorten:
    def test_shorten_anon_returns_201(self):
        url_doc = _make_url_doc()
        mock_svc = AsyncMock()
        mock_svc.create = AsyncMock(return_value=url_doc)

        application = _build_test_app(
            {get_current_user: lambda: None, get_url_service: lambda: mock_svc}
        )
        with TestClient(application, raise_server_exceptions=True) as client:
            resp = client.post(
                "/api/v1/shorten", json={"long_url": "https://example.com"}
            )

        assert resp.status_code == 201
        body = resp.json()
        assert body["alias"] == url_doc.alias
        assert "short_url" in body
        assert body["status"] == "ACTIVE"

    def test_shorten_with_alias(self):
        url_doc = _make_url_doc(alias="myalias")
        mock_svc = AsyncMock()
        mock_svc.create = AsyncMock(return_value=url_doc)

        application = _build_test_app(
            {get_current_user: lambda: None, get_url_service: lambda: mock_svc}
        )
        with TestClient(application, raise_server_exceptions=True) as client:
            resp = client.post(
                "/api/v1/shorten",
                json={"long_url": "https://example.com", "alias": "myalias"},
            )

        assert resp.status_code == 201
        assert resp.json()["alias"] == "myalias"

    def test_shorten_api_key_missing_scope_returns_403(self):
        key_doc = _make_api_key_doc(scopes=["stats:read"])  # wrong scope
        user = _make_user(api_key_doc=key_doc)

        application = _build_test_app(
            {get_current_user: lambda: user, get_url_service: lambda: AsyncMock()}
        )
        with TestClient(application, raise_server_exceptions=False) as client:
            resp = client.post(
                "/api/v1/shorten", json={"long_url": "https://example.com"}
            )

        assert resp.status_code == 403

    def test_shorten_api_key_admin_scope(self):
        user_id = ObjectId()
        url_doc = _make_url_doc(owner_id=user_id)
        key_doc = _make_api_key_doc(user_id=user_id, scopes=["admin:all"])
        user = _make_user(user_id=user_id, api_key_doc=key_doc)

        mock_svc = AsyncMock()
        mock_svc.create = AsyncMock(return_value=url_doc)

        application = _build_test_app(
            {get_current_user: lambda: user, get_url_service: lambda: mock_svc}
        )
        with TestClient(application, raise_server_exceptions=True) as client:
            resp = client.post(
                "/api/v1/shorten", json={"long_url": "https://example.com"}
            )

        assert resp.status_code == 201

    def test_shorten_missing_long_url_returns_422(self):
        application = _build_test_app(
            {get_current_user: lambda: None, get_url_service: lambda: AsyncMock()}
        )
        with TestClient(application, raise_server_exceptions=False) as client:
            resp = client.post("/api/v1/shorten", json={})

        assert resp.status_code == 422

    def test_shorten_validation_error_returns_400(self):
        mock_svc = AsyncMock()
        mock_svc.create = AsyncMock(side_effect=ValidationError("invalid URL"))

        application = _build_test_app(
            {get_current_user: lambda: None, get_url_service: lambda: mock_svc}
        )
        with TestClient(application, raise_server_exceptions=False) as client:
            resp = client.post(
                "/api/v1/shorten", json={"long_url": "https://example.com"}
            )

        assert resp.status_code == 400
        assert "error" in resp.json()

    def test_shorten_conflict_returns_409(self):
        mock_svc = AsyncMock()
        mock_svc.create = AsyncMock(side_effect=ConflictError("alias taken"))

        application = _build_test_app(
            {get_current_user: lambda: None, get_url_service: lambda: mock_svc}
        )
        with TestClient(application, raise_server_exceptions=False) as client:
            resp = client.post(
                "/api/v1/shorten",
                json={"long_url": "https://example.com", "alias": "taken"},
            )

        assert resp.status_code == 409


class TestShortenWithCustomDomain:
    """``domain`` field on POST /shorten triggers owner+ACTIVE check."""

    def test_anonymous_user_cannot_use_custom_domain(self):
        from dependencies import get_custom_domain_service

        url_svc = AsyncMock()
        custom_svc = AsyncMock()
        custom_svc.assert_owned_and_active = AsyncMock(return_value=None)
        application = _build_test_app(
            {
                get_current_user: lambda: None,
                get_url_service: lambda: url_svc,
                get_custom_domain_service: lambda: custom_svc,
            }
        )
        with TestClient(application, raise_server_exceptions=False) as client:
            resp = client.post(
                "/api/v1/shorten",
                json={
                    "long_url": "https://example.com",
                    "domain": "links.acme.com",
                },
            )
        assert resp.status_code == 401
        assert custom_svc.assert_owned_and_active.await_count == 0
        url_svc.create.assert_not_called()

    def test_authed_user_with_owned_active_domain_succeeds(self):
        from dependencies import get_custom_domain_service

        user = _make_user(email_verified=True)
        url_doc = _make_url_doc(owner_id=user.user_id)
        url_doc.domain = "links.acme.com"
        url_svc = AsyncMock()
        url_svc.create = AsyncMock(return_value=url_doc)

        custom_svc = AsyncMock()
        custom_svc.assert_owned_and_active = AsyncMock(return_value=None)

        application = _build_test_app(
            {
                get_current_user: lambda: user,
                get_url_service: lambda: url_svc,
                get_custom_domain_service: lambda: custom_svc,
            }
        )
        with TestClient(application, raise_server_exceptions=True) as client:
            resp = client.post(
                "/api/v1/shorten",
                json={
                    "long_url": "https://example.com",
                    "domain": "links.acme.com",
                },
            )
        assert resp.status_code == 201
        body = resp.json()
        # short_url is built off the custom host, not the system default.
        assert body["short_url"].startswith("https://links.acme.com/")
        # Owner check fired with the normalised fqdn.
        custom_svc.assert_owned_and_active.assert_awaited_once()
        # Service got the domain on the create call.
        kwargs = url_svc.create.call_args.kwargs
        assert kwargs.get("domain") == "links.acme.com"
