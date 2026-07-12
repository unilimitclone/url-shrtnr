"""Unit tests for dependencies/auth.py — get_current_user and guards."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import jwt as pyjwt
import pytest
from bson import ObjectId

from dependencies.auth import (
    CurrentUser,
    check_api_key_scope,
    get_current_user,
    require_auth,
    require_verified_email,
)
from errors import AuthenticationError, EmailNotVerifiedError, ForbiddenError
from schemas.models.api_key import ApiKeyDoc

USER_OID = ObjectId("aaaaaaaaaaaaaaaaaaaaaaaa")
KEY_OID = ObjectId("cccccccccccccccccccccccc")
JWT_SECRET = "test-secret-key-at-least-32-chars!!"
JWT_ISSUER = "spoo.me"
JWT_AUDIENCE = "spoo.me.api"


# ── Helpers ───────────────────────────────────────────────────────────────────


def make_jwt_settings():
    from config import JWTSettings

    return JWTSettings(
        jwt_issuer=JWT_ISSUER,
        jwt_audience=JWT_AUDIENCE,
        access_token_ttl_seconds=900,
        refresh_token_ttl_seconds=2592000,
        jwt_secret=JWT_SECRET,
        jwt_private_key="",
        jwt_public_key="",
    )


def make_settings():
    s = MagicMock()
    s.jwt = make_jwt_settings()
    return s


def make_request(auth_header: str = "", cookies: dict | None = None):
    req = MagicMock()
    req.headers.get = lambda key, default="": (
        auth_header if key == "Authorization" else default
    )
    req.cookies.get = lambda key, default=None: (cookies or {}).get(key, default)
    return req


def make_key_doc(revoked: bool = False, expires_at=None, scopes=None):
    return ApiKeyDoc.from_mongo(
        {
            "_id": KEY_OID,
            "user_id": USER_OID,
            "token_prefix": "abcd1234",
            "token_hash": "x" * 64,
            "name": "Test Key",
            "scopes": scopes or ["urls:read"],
            "revoked": revoked,
            "expires_at": expires_at,
            "created_at": datetime.now(timezone.utc),
        }
    )


def make_jwt_token(
    token_type: str = "access",
    ttl_seconds: int = 900,
    email: str | None = None,
):
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(USER_OID),
        "email_verified": True,
        "type": token_type,
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
        "iat": now,
        "exp": now + timedelta(seconds=ttl_seconds),
    }
    if email is not None:
        payload["email"] = email
    return pyjwt.encode(payload, JWT_SECRET, algorithm="HS256")


# ── TestGetCurrentUser ────────────────────────────────────────────────────────


class TestGetCurrentUser:
    @pytest.mark.asyncio
    async def test_no_auth_returns_none(self):
        req = make_request()
        with patch("dependencies.auth.get_settings", return_value=make_settings()):
            result = await get_current_user(req, db=MagicMock())
        assert result is None

    @pytest.mark.asyncio
    async def test_api_key_valid_returns_current_user(self):
        key_doc = make_key_doc()
        user_mock = MagicMock(email_verified=True, email="Owner@Example.com")

        with (
            patch("dependencies.auth.get_settings", return_value=make_settings()),
            patch("dependencies.auth.ApiKeyRepository") as MockKeyRepo,
            patch("dependencies.auth.UserRepository") as MockUserRepo,
        ):
            MockKeyRepo.return_value.find_by_hash = AsyncMock(return_value=key_doc)
            MockUserRepo.return_value.find_by_id = AsyncMock(return_value=user_mock)

            req = make_request(auth_header="Bearer spoo_testrawtoken123")
            result = await get_current_user(req, db=MagicMock())

        assert result is not None
        assert result.user_id == USER_OID
        assert result.api_key_doc == key_doc
        assert result.email_verified is True
        # Email comes from the owning UserDoc (already fetched), lowercased.
        assert result.email == "owner@example.com"

    @pytest.mark.asyncio
    async def test_api_key_revoked_returns_none(self):
        key_doc = make_key_doc(revoked=True)

        with (
            patch("dependencies.auth.get_settings", return_value=make_settings()),
            patch("dependencies.auth.ApiKeyRepository") as MockKeyRepo,
        ):
            MockKeyRepo.return_value.find_by_hash = AsyncMock(return_value=key_doc)

            req = make_request(auth_header="Bearer spoo_testrawtoken123")
            result = await get_current_user(req, db=MagicMock())

        assert result is None

    @pytest.mark.asyncio
    async def test_api_key_expired_returns_none(self):
        expired = datetime(2020, 1, 1, tzinfo=timezone.utc)
        key_doc = make_key_doc(expires_at=expired)

        with (
            patch("dependencies.auth.get_settings", return_value=make_settings()),
            patch("dependencies.auth.ApiKeyRepository") as MockKeyRepo,
        ):
            MockKeyRepo.return_value.find_by_hash = AsyncMock(return_value=key_doc)

            req = make_request(auth_header="Bearer spoo_testrawtoken123")
            result = await get_current_user(req, db=MagicMock())

        assert result is None

    @pytest.mark.asyncio
    async def test_api_key_not_found_returns_none(self):
        with (
            patch("dependencies.auth.get_settings", return_value=make_settings()),
            patch("dependencies.auth.ApiKeyRepository") as MockKeyRepo,
        ):
            MockKeyRepo.return_value.find_by_hash = AsyncMock(return_value=None)

            req = make_request(auth_header="Bearer spoo_notfound")
            result = await get_current_user(req, db=MagicMock())

        assert result is None

    @pytest.mark.asyncio
    async def test_api_key_repo_error_returns_none(self):
        with (
            patch("dependencies.auth.get_settings", return_value=make_settings()),
            patch("dependencies.auth.ApiKeyRepository") as MockKeyRepo,
        ):
            MockKeyRepo.return_value.find_by_hash = AsyncMock(
                side_effect=RuntimeError("db error")
            )

            req = make_request(auth_header="Bearer spoo_sometoken")
            result = await get_current_user(req, db=MagicMock())

        assert result is None

    @pytest.mark.asyncio
    async def test_jwt_valid_returns_current_user(self):
        token = make_jwt_token()
        req = make_request(auth_header=f"Bearer {token}")

        with patch("dependencies.auth.get_settings", return_value=make_settings()):
            result = await get_current_user(req, db=MagicMock())

        assert result is not None
        assert result.user_id == USER_OID
        assert result.email_verified is True
        assert result.api_key_doc is None

    @pytest.mark.asyncio
    async def test_jwt_email_claim_populates_current_user_lowercased(self):
        token = make_jwt_token(email="Alice@Example.COM")
        req = make_request(auth_header=f"Bearer {token}")

        with patch("dependencies.auth.get_settings", return_value=make_settings()):
            result = await get_current_user(req, db=MagicMock())

        assert result is not None
        assert result.email == "alice@example.com"

    @pytest.mark.asyncio
    async def test_jwt_without_email_claim_yields_none_email(self):
        # Old access tokens minted before the "email" claim existed must
        # still authenticate — email is simply None, never an error.
        token = make_jwt_token()
        req = make_request(auth_header=f"Bearer {token}")

        with patch("dependencies.auth.get_settings", return_value=make_settings()):
            result = await get_current_user(req, db=MagicMock())

        assert result is not None
        assert result.email is None

    @pytest.mark.asyncio
    async def test_jwt_blank_email_claim_yields_none_email(self):
        token = make_jwt_token(email="   ")
        req = make_request(auth_header=f"Bearer {token}")

        with patch("dependencies.auth.get_settings", return_value=make_settings()):
            result = await get_current_user(req, db=MagicMock())

        assert result is not None
        assert result.email is None

    @pytest.mark.asyncio
    @pytest.mark.parametrize("bad_email", [42, ["alice@example.com"]])
    async def test_jwt_non_string_email_claim_yields_none_email(self, bad_email):
        # A token whose "email" claim is not a string (int, list, …) must
        # still authenticate — the claim parses to None, never an error.
        token = make_jwt_token(email=bad_email)
        req = make_request(auth_header=f"Bearer {token}")

        with patch("dependencies.auth.get_settings", return_value=make_settings()):
            result = await get_current_user(req, db=MagicMock())

        assert result is not None
        assert result.user_id == USER_OID
        assert result.email is None

    @pytest.mark.asyncio
    async def test_token_factory_round_trip_populates_email(self):
        # Mint with the real TokenFactory → resolve via get_current_user:
        # the email claim survives the round trip and is lowercased.
        from schemas.models.user import UserDoc
        from services.token_factory import TokenFactory

        user_doc = UserDoc.from_mongo(
            {
                "_id": USER_OID,
                "email": "Round.Trip@Example.COM",
                "email_verified": True,
                "user_name": "Round Trip",
                "created_at": datetime.now(timezone.utc),
                "updated_at": datetime.now(timezone.utc),
            }
        )
        token = TokenFactory(make_jwt_settings()).generate_access_token(
            user_doc, amr="pwd"
        )
        req = make_request(auth_header=f"Bearer {token}")

        with patch("dependencies.auth.get_settings", return_value=make_settings()):
            result = await get_current_user(req, db=MagicMock())

        assert result is not None
        assert result.user_id == USER_OID
        assert result.email == "round.trip@example.com"

    @pytest.mark.asyncio
    async def test_jwt_refresh_token_rejected(self):
        token = make_jwt_token(token_type="refresh")
        req = make_request(auth_header=f"Bearer {token}")

        with patch("dependencies.auth.get_settings", return_value=make_settings()):
            result = await get_current_user(req, db=MagicMock())

        assert result is None

    @pytest.mark.asyncio
    async def test_jwt_invalid_returns_none(self):
        req = make_request(auth_header="Bearer not.a.valid.jwt")

        with patch("dependencies.auth.get_settings", return_value=make_settings()):
            result = await get_current_user(req, db=MagicMock())

        assert result is None

    @pytest.mark.asyncio
    async def test_jwt_from_cookie_returns_current_user(self):
        token = make_jwt_token()
        req = make_request(cookies={"access_token": token})

        with patch("dependencies.auth.get_settings", return_value=make_settings()):
            result = await get_current_user(req, db=MagicMock())

        assert result is not None
        assert result.user_id == USER_OID


# ── TestRequireAuth ───────────────────────────────────────────────────────────


class TestRequireAuth:
    @pytest.mark.asyncio
    async def test_raises_when_no_user(self):
        with pytest.raises(AuthenticationError):
            await require_auth(user=None)

    @pytest.mark.asyncio
    async def test_passes_through_authenticated_user(self):
        user = CurrentUser(user_id=USER_OID, email_verified=True)
        result = await require_auth(user=user)
        assert result is user


# ── TestRequireVerifiedEmail ──────────────────────────────────────────────────


class TestRequireVerifiedEmail:
    @pytest.mark.asyncio
    async def test_raises_when_email_not_verified(self):
        user = CurrentUser(user_id=USER_OID, email_verified=False)
        with pytest.raises(EmailNotVerifiedError):
            await require_verified_email(user=user)

    @pytest.mark.asyncio
    async def test_passes_through_verified_user(self):
        user = CurrentUser(user_id=USER_OID, email_verified=True)
        result = await require_verified_email(user=user)
        assert result is user


# ── TestCheckApiKeyScope ──────────────────────────────────────────────────────


class TestCheckApiKeyScope:
    def test_raises_when_scope_missing(self):
        key_doc = make_key_doc(scopes=["urls:read"])
        user = CurrentUser(user_id=USER_OID, email_verified=True, api_key_doc=key_doc)
        with pytest.raises(ForbiddenError):
            check_api_key_scope(user, {"urls:manage"})

    def test_passes_when_scope_present(self):
        key_doc = make_key_doc(scopes=["urls:manage"])
        user = CurrentUser(user_id=USER_OID, email_verified=True, api_key_doc=key_doc)
        check_api_key_scope(user, {"urls:manage"})  # no raise

    def test_passes_when_scope_overlaps(self):
        key_doc = make_key_doc(scopes=["urls:read", "urls:manage"])
        user = CurrentUser(user_id=USER_OID, email_verified=True, api_key_doc=key_doc)
        check_api_key_scope(user, {"urls:manage", "admin:all"})  # intersection exists

    def test_jwt_user_bypasses_scope_check(self):
        user = CurrentUser(user_id=USER_OID, email_verified=True)  # no api_key_doc
        check_api_key_scope(user, {"url:write"})  # no raise

    def test_anonymous_bypasses_scope_check(self):
        check_api_key_scope(None, {"url:write"})  # no raise
