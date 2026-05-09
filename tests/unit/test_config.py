"""Unit tests for AppSettings and sub-configs."""

import pytest
from pydantic import ValidationError as PydanticValidationError

from config import (
    AppSettings,
    DatabaseSettings,
    JWTSettings,
    RedisSettings,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def with_mongo(monkeypatch):
    """Set the required MONGODB_URI so AppSettings can be instantiated."""
    monkeypatch.setenv("MONGODB_URI", "mongodb://localhost:27017/")
    return monkeypatch


# ---------------------------------------------------------------------------
# DatabaseSettings
# ---------------------------------------------------------------------------


class TestDatabaseSettings:
    def test_loads_mongodb_uri(self, monkeypatch):
        monkeypatch.setenv("MONGODB_URI", "mongodb://localhost:27017/")
        assert DatabaseSettings().mongodb_uri == "mongodb://localhost:27017/"

    def test_default_db_name(self, monkeypatch):
        monkeypatch.setenv("MONGODB_URI", "mongodb://localhost:27017/")
        assert DatabaseSettings().db_name == "url-shortener"

    def test_missing_mongodb_uri_raises(self, monkeypatch):
        monkeypatch.delenv("MONGODB_URI", raising=False)
        with pytest.raises((PydanticValidationError, Exception)):
            DatabaseSettings()


# ---------------------------------------------------------------------------
# RedisSettings
# ---------------------------------------------------------------------------


class TestRedisSettings:
    def test_redis_uri_optional(self, monkeypatch):
        monkeypatch.delenv("REDIS_URI", raising=False)
        assert RedisSettings().redis_uri is None

    def test_redis_uri_loaded(self, monkeypatch):
        monkeypatch.setenv("REDIS_URI", "redis://localhost:6379")
        assert RedisSettings().redis_uri == "redis://localhost:6379"

    def test_default_ttl(self, monkeypatch):
        monkeypatch.delenv("REDIS_TTL_SECONDS", raising=False)
        assert RedisSettings().redis_ttl_seconds == 3600


# ---------------------------------------------------------------------------
# JWTSettings
# ---------------------------------------------------------------------------


class TestJWTSettings:
    def test_defaults(self, monkeypatch):
        for var in (
            "JWT_ISSUER",
            "JWT_AUDIENCE",
            "ACCESS_TOKEN_TTL_SECONDS",
            "REFRESH_TOKEN_TTL_SECONDS",
            "COOKIE_SECURE",
            "JWT_PRIVATE_KEY",
            "JWT_PUBLIC_KEY",
            "JWT_SECRET",
        ):
            monkeypatch.delenv(var, raising=False)
        s = JWTSettings()
        assert s.jwt_issuer == "spoo.me"
        assert s.jwt_audience == "spoo.me.api"
        assert s.access_token_ttl_seconds == 900
        assert s.refresh_token_ttl_seconds == 2592000


@pytest.mark.parametrize(
    "private_key, public_key, expected",
    [
        ("private", "public", True),
        (None, None, False),
    ],
    ids=["keys_present", "keys_absent"],
)
def test_jwt_use_rs256(monkeypatch, private_key, public_key, expected):
    if private_key:
        monkeypatch.setenv("JWT_PRIVATE_KEY", private_key)
        monkeypatch.setenv("JWT_PUBLIC_KEY", public_key)
    else:
        monkeypatch.delenv("JWT_PRIVATE_KEY", raising=False)
        monkeypatch.delenv("JWT_PUBLIC_KEY", raising=False)
    assert JWTSettings().use_rs256 is expected


# ---------------------------------------------------------------------------
# AppSettings
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "env, expected",
    [("production", True), ("development", False)],
    ids=["production", "development"],
)
def test_is_production(with_mongo, env, expected):
    with_mongo.setenv("ENV", env)
    assert AppSettings().is_production is expected


@pytest.mark.parametrize(
    "secret_key, flask_secret_key, expected",
    [
        (None, "flask-secret", "flask-secret"),  # falls back to FLASK_SECRET_KEY
        ("new-secret", "old-secret", "new-secret"),  # SECRET_KEY takes precedence
    ],
    ids=["flask_fallback", "secret_key_wins"],
)
def test_secret_key_resolution(with_mongo, secret_key, flask_secret_key, expected):
    if secret_key:
        with_mongo.setenv("SECRET_KEY", secret_key)
    else:
        with_mongo.delenv("SECRET_KEY", raising=False)
    with_mongo.setenv("FLASK_SECRET_KEY", flask_secret_key)
    assert AppSettings().secret_key == expected


class TestAppSettings:
    def test_sub_configs_populated(self, with_mongo):
        s = AppSettings()
        for attr in ("db", "redis", "jwt", "oauth", "email", "logging", "sentry"):
            assert getattr(s, attr) is not None, f"sub-config '{attr}' is None"

    def test_cors_origins_default(self, with_mongo):
        assert AppSettings().cors_origins == ["*"]


class TestSystemDefaultDomain:
    """AppSettings.system_default_domain — fail-hard derivation from app_url."""

    def test_extracts_fqdn_from_app_url(self, with_mongo):
        with_mongo.setenv("APP_URL", "https://spoo.me")
        assert AppSettings().system_default_domain == "spoo.me"

    def test_lowercases(self, with_mongo):
        with_mongo.setenv("APP_URL", "https://SPOO.ME")
        assert AppSettings().system_default_domain == "spoo.me"

    def test_strips_port(self, with_mongo):
        with_mongo.setenv("APP_URL", "http://localhost:8000")
        assert AppSettings().system_default_domain == "localhost"

    def test_self_hoster_domain(self, with_mongo):
        with_mongo.setenv("APP_URL", "https://my.shortener.dev")
        assert AppSettings().system_default_domain == "my.shortener.dev"

    def test_strips_trailing_dot(self, with_mongo):
        # Fully qualified DNS notation includes a trailing dot for the root.
        # Strip it so the canonical form matches everywhere.
        with_mongo.setenv("APP_URL", "https://spoo.me./")
        assert AppSettings().system_default_domain == "spoo.me"

    def test_raises_on_missing_scheme(self, with_mongo):
        # Bare domain, no scheme → urlparse can't extract hostname.
        with_mongo.setenv("APP_URL", "spoo.me")
        with pytest.raises(ValueError, match="APP_URL is missing or invalid"):
            _ = AppSettings().system_default_domain

    def test_raises_on_empty(self, with_mongo):
        with_mongo.setenv("APP_URL", "")
        with pytest.raises(ValueError, match="APP_URL is missing or invalid"):
            _ = AppSettings().system_default_domain

    def test_raises_on_garbage(self, with_mongo):
        with_mongo.setenv("APP_URL", "not a url")
        with pytest.raises(ValueError, match="APP_URL is missing or invalid"):
            _ = AppSettings().system_default_domain

    def test_blocked_self_domains_derives_from_default(self, with_mongo):
        with_mongo.setenv("APP_URL", "https://spoo.me")
        assert AppSettings().blocked_self_domains == ("spoo.me",)
