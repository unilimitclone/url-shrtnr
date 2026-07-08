"""
Unit tests for Phase 7 — UrlService.

All external dependencies (repositories, cache) are replaced with AsyncMock.
Tests verify behavior, not implementation details.
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock

import pytest
from bson import ObjectId

from errors import (
    BlockedUrlError,
    ConflictError,
    ForbiddenError,
    GoneError,
    NotFoundError,
    ValidationError,
)
from infrastructure.cache.url_cache import UrlCacheData
from schemas.models.base import ANONYMOUS_OWNER_ID
from schemas.models.url import EmojiUrlDoc, LegacyUrlDoc, UrlV2Doc

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

USER_OID = ObjectId("aaaaaaaaaaaaaaaaaaaaaaaa")
URL_OID = ObjectId("bbbbbbbbbbbbbbbbbbbbbbbb")
ALIAS = "abc1234"
SYSTEM_DEFAULT_DOMAIN = "spoo.me"


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────


def make_url_v2_doc(
    alias: str = ALIAS,
    url_id: ObjectId = URL_OID,
    owner_id: ObjectId = USER_OID,
    status: str = "ACTIVE",
    block_bots: bool | None = None,
    max_clicks: int | None = None,
    password: str | None = None,
    expire_after: datetime | None = None,
    domain: str | None = None,
    meta_tags: dict | None = None,
) -> UrlV2Doc:
    return UrlV2Doc.from_mongo(
        {
            "_id": url_id,
            "alias": alias,
            "owner_id": owner_id,
            "domain": domain if domain is not None else SYSTEM_DEFAULT_DOMAIN,
            "created_at": datetime(2024, 1, 1, tzinfo=timezone.utc),
            "creation_ip": "1.2.3.4",
            "long_url": "https://example.com",
            "password": password,
            "block_bots": block_bots,
            "max_clicks": max_clicks,
            "expire_after": expire_after,
            "status": status,
            "private_stats": True,
            "total_clicks": 0,
            "last_click": None,
            "meta_tags": meta_tags,
        }
    )


def make_legacy_doc(
    short_code: str = "abcdef",
    url: str = "https://legacy.example.com",
    block_bots: bool = False,
    max_clicks: int | None = None,
    password: str | None = None,
) -> LegacyUrlDoc:
    return LegacyUrlDoc.from_mongo(
        {
            "_id": short_code,
            "url": url,
            "block-bots": block_bots,
            "max-clicks": max_clicks,
            "total-clicks": 0,
            "password": password,
        }
    )


def make_emoji_doc(short_code: str = "🐍🔥💎") -> EmojiUrlDoc:
    return EmojiUrlDoc.from_mongo(
        {
            "_id": short_code,
            "url": "https://emoji.example.com",
            "block-bots": False,
            "total-clicks": 0,
        }
    )


def make_active_cache(
    schema: str = "v2",
    alias: str = ALIAS,
    block_bots: bool = False,
    max_clicks: int | None = None,
    password_hash: str | None = None,
) -> UrlCacheData:
    return UrlCacheData(
        id=str(URL_OID),
        alias=alias,
        long_url="https://example.com",
        block_bots=block_bots,
        password_hash=password_hash,
        expiration_time=None,
        max_clicks=max_clicks,
        url_status="ACTIVE",
        schema_version=schema,
        owner_id=str(USER_OID),
    )


def make_repos():
    url_repo = AsyncMock()
    legacy_repo = AsyncMock()
    emoji_repo = AsyncMock()
    blocked_url_repo = AsyncMock()
    url_cache = AsyncMock()
    return url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache


def make_service(url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache):
    from services.url_service import UrlService

    return UrlService(
        url_repo=url_repo,
        legacy_repo=legacy_repo,
        emoji_repo=emoji_repo,
        blocked_url_repo=blocked_url_repo,
        url_cache=url_cache,
        blocked_self_domains=[SYSTEM_DEFAULT_DOMAIN],
        system_default_domain=SYSTEM_DEFAULT_DOMAIN,
    )


# ─────────────────────────────────────────────────────────────────────────────
# TestUrlServiceResolve
# ─────────────────────────────────────────────────────────────────────────────


class TestUrlServiceResolve:
    @pytest.mark.asyncio
    async def test_cache_hit_active_v2_returns_data(self):
        url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache = make_repos()
        svc = make_service(
            url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache
        )

        cached = make_active_cache(schema="v2")
        url_cache.get.return_value = cached

        result, schema = await svc.resolve(ALIAS)

        assert result is cached
        assert schema == "v2"
        url_repo.find_by_alias.assert_not_called()

    @pytest.mark.asyncio
    async def test_cache_hit_blocked_v2_raises_blocked_url_error(self):
        url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache = make_repos()
        svc = make_service(
            url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache
        )

        cached = UrlCacheData(
            id=str(URL_OID),
            alias=ALIAS,
            long_url="",
            block_bots=False,
            password_hash=None,
            expiration_time=None,
            max_clicks=None,
            url_status="BLOCKED",
            schema_version="v2",
            owner_id=str(USER_OID),
        )
        url_cache.get.return_value = cached

        with pytest.raises(BlockedUrlError):
            await svc.resolve(ALIAS)

    @pytest.mark.asyncio
    async def test_cache_hit_expired_v2_raises_gone(self):
        url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache = make_repos()
        svc = make_service(
            url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache
        )

        for status in ("EXPIRED", "INACTIVE"):
            url_cache.get.return_value = UrlCacheData(
                id=str(URL_OID),
                alias=ALIAS,
                long_url="",
                block_bots=False,
                password_hash=None,
                expiration_time=None,
                max_clicks=None,
                url_status=status,
                schema_version="v2",
                owner_id=str(USER_OID),
            )
            with pytest.raises(GoneError):
                await svc.resolve(ALIAS)

    @pytest.mark.asyncio
    async def test_cache_miss_7char_tries_v2_first(self):
        url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache = make_repos()
        svc = make_service(
            url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache
        )

        url_cache.get.return_value = None
        doc = make_url_v2_doc(alias="abc1234")
        url_repo.find_by_alias.return_value = doc

        result, schema = await svc.resolve("abc1234")

        assert schema == "v2"
        assert result.alias == "abc1234"
        url_repo.find_by_alias.assert_called_once_with("abc1234", SYSTEM_DEFAULT_DOMAIN)
        legacy_repo.find_by_id.assert_not_called()

    @pytest.mark.asyncio
    async def test_cache_miss_7char_falls_back_to_v1(self):
        url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache = make_repos()
        svc = make_service(
            url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache
        )

        url_cache.get.return_value = None
        url_repo.find_by_alias.return_value = None
        doc = make_legacy_doc(short_code="abc1234")
        legacy_repo.find_by_id.return_value = doc

        _result, schema = await svc.resolve("abc1234")

        assert schema == "v1"
        url_repo.find_by_alias.assert_called_once_with("abc1234", SYSTEM_DEFAULT_DOMAIN)
        legacy_repo.find_by_id.assert_called_once_with("abc1234")

    @pytest.mark.asyncio
    async def test_cache_miss_6char_tries_v1_first(self):
        url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache = make_repos()
        svc = make_service(
            url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache
        )

        url_cache.get.return_value = None
        doc = make_legacy_doc(short_code="abcdef")
        legacy_repo.find_by_id.return_value = doc

        _result, schema = await svc.resolve("abcdef")

        assert schema == "v1"
        legacy_repo.find_by_id.assert_called_once_with("abcdef")
        url_repo.find_by_alias.assert_not_called()

    @pytest.mark.asyncio
    async def test_cache_miss_6char_falls_back_to_v2(self):
        url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache = make_repos()
        svc = make_service(
            url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache
        )

        url_cache.get.return_value = None
        legacy_repo.find_by_id.return_value = None
        doc = make_url_v2_doc(alias="abcdef")
        url_repo.find_by_alias.return_value = doc

        _result, schema = await svc.resolve("abcdef")

        assert schema == "v2"
        legacy_repo.find_by_id.assert_called_once_with("abcdef")
        url_repo.find_by_alias.assert_called_once_with("abcdef", SYSTEM_DEFAULT_DOMAIN)

    @pytest.mark.asyncio
    async def test_cache_miss_emoji_resolves_emoji_schema(self):
        url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache = make_repos()
        svc = make_service(
            url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache
        )

        url_cache.get.return_value = None
        emoji_doc = make_emoji_doc("🐍🔥💎")
        emoji_repo.find_by_id.return_value = emoji_doc

        _result, schema = await svc.resolve("🐍🔥💎")

        assert schema == "emoji"
        emoji_repo.find_by_id.assert_called_once_with("🐍🔥💎")
        url_repo.find_by_alias.assert_not_called()
        legacy_repo.find_by_id.assert_not_called()

    @pytest.mark.asyncio
    async def test_cache_miss_other_length_tries_v2_first(self):
        url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache = make_repos()
        svc = make_service(
            url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache
        )

        url_cache.get.return_value = None
        doc = make_url_v2_doc(alias="customalias")
        url_repo.find_by_alias.return_value = doc

        _result, schema = await svc.resolve("customalias")

        assert schema == "v2"
        url_repo.find_by_alias.assert_called_once_with(
            "customalias", SYSTEM_DEFAULT_DOMAIN
        )

    @pytest.mark.asyncio
    async def test_cache_miss_not_found_raises_not_found(self):
        url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache = make_repos()
        svc = make_service(
            url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache
        )

        url_cache.get.return_value = None
        url_repo.find_by_alias.return_value = None
        legacy_repo.find_by_id.return_value = None

        with pytest.raises(NotFoundError):
            await svc.resolve("missing")

    @pytest.mark.asyncio
    async def test_db_miss_v2_blocked_caches_minimal_then_raises(self):
        url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache = make_repos()
        svc = make_service(
            url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache
        )

        url_cache.get.return_value = None
        blocked_doc = make_url_v2_doc(alias=ALIAS, status="BLOCKED")
        url_repo.find_by_alias.return_value = blocked_doc

        with pytest.raises(BlockedUrlError):
            await svc.resolve(ALIAS)

        # Cache should have been populated (even for blocked URLs)
        url_cache.set.assert_called_once()

    @pytest.mark.asyncio
    async def test_v1_with_max_clicks_not_cached(self):
        url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache = make_repos()
        svc = make_service(
            url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache
        )

        url_cache.get.return_value = None
        legacy_repo.find_by_id.return_value = make_legacy_doc(
            short_code="abcdef", max_clicks=10
        )

        await svc.resolve("abcdef")

        url_cache.set.assert_not_called()

    @pytest.mark.asyncio
    async def test_v1_without_max_clicks_is_cached(self):
        url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache = make_repos()
        svc = make_service(
            url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache
        )

        url_cache.get.return_value = None
        legacy_repo.find_by_id.return_value = make_legacy_doc(short_code="abcdef")

        await svc.resolve("abcdef")

        url_cache.set.assert_called_once()

    @pytest.mark.asyncio
    async def test_custom_domain_scope_only_hits_v2_with_domain(self):
        url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache = make_repos()
        svc = make_service(
            url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache
        )
        url_cache.get.return_value = None
        doc = make_url_v2_doc(alias=ALIAS, domain="links.acme.com")
        url_repo.find_by_alias.return_value = doc

        result, schema = await svc.resolve(ALIAS, domain="links.acme.com")

        assert schema == "v2"
        assert result.alias == ALIAS
        url_repo.find_by_alias.assert_called_once_with(ALIAS, "links.acme.com")
        legacy_repo.find_by_id.assert_not_called()
        emoji_repo.find_by_id.assert_not_called()
        url_cache.get.assert_called_once_with(ALIAS, "links.acme.com")

    @pytest.mark.asyncio
    async def test_custom_domain_unknown_alias_raises_not_found(self):
        url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache = make_repos()
        svc = make_service(
            url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache
        )
        url_cache.get.return_value = None
        url_repo.find_by_alias.return_value = None

        with pytest.raises(NotFoundError):
            await svc.resolve("absent", domain="links.acme.com")


# ─────────────────────────────────────────────────────────────────────────────
# TestUrlServiceCreate
# ─────────────────────────────────────────────────────────────────────────────


class TestUrlServiceCreate:
    @pytest.mark.asyncio
    async def test_creates_url_with_generated_alias(self):
        url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache = make_repos()
        svc = make_service(
            url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache
        )

        blocked_url_repo.get_patterns.return_value = []
        url_repo.check_alias_exists.return_value = False
        url_repo.insert.return_value = URL_OID

        from schemas.dto.requests.url import CreateUrlRequest

        req = CreateUrlRequest(long_url="https://example.com")
        result = await svc.create(req, owner_id=USER_OID, client_ip="1.2.3.4")

        assert result.long_url == "https://example.com"
        url_repo.insert.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_with_custom_alias_checks_v2_uniqueness(self):
        url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache = make_repos()
        svc = make_service(
            url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache
        )

        blocked_url_repo.get_patterns.return_value = []
        # Alias does NOT exist in v2 or v1
        url_repo.check_alias_exists.return_value = False
        legacy_repo.check_exists.return_value = False
        url_repo.insert.return_value = URL_OID

        from schemas.dto.requests.url import CreateUrlRequest

        req = CreateUrlRequest(long_url="https://example.com", alias="myalias")
        await svc.create(req, owner_id=USER_OID, client_ip="1.2.3.4")

        url_repo.check_alias_exists.assert_called_with("myalias", SYSTEM_DEFAULT_DOMAIN)

    @pytest.mark.asyncio
    async def test_create_with_custom_alias_checks_v1_uniqueness(self):
        url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache = make_repos()
        svc = make_service(
            url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache
        )

        blocked_url_repo.get_patterns.return_value = []
        # Not in v2
        url_repo.check_alias_exists.return_value = False
        # Exists in v1 → should reject
        legacy_repo.check_exists.return_value = True

        from schemas.dto.requests.url import CreateUrlRequest

        req = CreateUrlRequest(long_url="https://example.com", alias="myalias")
        with pytest.raises(ConflictError):
            await svc.create(req, owner_id=USER_OID, client_ip="1.2.3.4")

    @pytest.mark.asyncio
    async def test_create_blocked_url_raises_validation_error(self):
        url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache = make_repos()
        svc = make_service(
            url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache
        )

        blocked_url_repo.get_patterns.return_value = [r"https://evil\.com"]

        from schemas.dto.requests.url import CreateUrlRequest

        req = CreateUrlRequest(long_url="https://evil.com/page")
        with pytest.raises(ValidationError):
            await svc.create(req, owner_id=USER_OID, client_ip="1.2.3.4")

    @pytest.mark.asyncio
    async def test_create_self_link_raises_validation_error(self):
        url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache = make_repos()
        svc = make_service(
            url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache
        )

        blocked_url_repo.get_patterns.return_value = []

        from schemas.dto.requests.url import CreateUrlRequest

        req = CreateUrlRequest(long_url="https://spoo.me/abc")
        with pytest.raises(ValidationError):
            await svc.create(req, owner_id=USER_OID, client_ip="1.2.3.4")

    @pytest.mark.asyncio
    async def test_create_hashes_password(self):
        url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache = make_repos()
        svc = make_service(
            url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache
        )

        blocked_url_repo.get_patterns.return_value = []
        url_repo.check_alias_exists.return_value = False
        url_repo.insert.return_value = URL_OID

        from schemas.dto.requests.url import CreateUrlRequest

        req = CreateUrlRequest(long_url="https://example.com", password="Secret1!")
        await svc.create(req, owner_id=USER_OID, client_ip="1.2.3.4")

        # password in DB doc should be a hash, not plaintext
        inserted_doc = url_repo.insert.call_args[0][0]
        assert inserted_doc["password"] != "Secret1!"
        assert inserted_doc["password"] is not None

    @pytest.mark.asyncio
    async def test_create_anonymous_owner_uses_sentinel(self):
        url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache = make_repos()
        svc = make_service(
            url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache
        )

        blocked_url_repo.get_patterns.return_value = []
        url_repo.check_alias_exists.return_value = False  # needed for alias generation
        url_repo.insert.return_value = URL_OID

        from schemas.dto.requests.url import CreateUrlRequest

        req = CreateUrlRequest(long_url="https://example.com")
        await svc.create(req, owner_id=None, client_ip="1.2.3.4")

        inserted_doc = url_repo.insert.call_args[0][0]
        assert inserted_doc["owner_id"] == ANONYMOUS_OWNER_ID

    @pytest.mark.asyncio
    async def test_create_stamps_system_default_domain(self):
        # Regression: empty domain on insert silently shadows real shorts under
        # the compound unique index. Service must always stamp it.
        url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache = make_repos()
        svc = make_service(
            url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache
        )

        blocked_url_repo.get_patterns.return_value = []
        url_repo.check_alias_exists.return_value = False
        url_repo.insert.return_value = URL_OID

        from schemas.dto.requests.url import CreateUrlRequest

        req = CreateUrlRequest(long_url="https://example.com")
        await svc.create(req, owner_id=USER_OID, client_ip="1.2.3.4")

        inserted_doc = url_repo.insert.call_args[0][0]
        assert inserted_doc["domain"] == SYSTEM_DEFAULT_DOMAIN

    @pytest.mark.asyncio
    async def test_create_future_expire_after_is_accepted(self):
        url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache = make_repos()
        svc = make_service(
            url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache
        )

        blocked_url_repo.get_patterns.return_value = []
        url_repo.check_alias_exists.return_value = False
        url_repo.insert.return_value = URL_OID

        from schemas.dto.requests.url import CreateUrlRequest

        # far future unix timestamp
        future_ts = 9999999999
        req = CreateUrlRequest(long_url="https://example.com", expire_after=future_ts)
        await svc.create(req, owner_id=USER_OID, client_ip="1.2.3.4")

        inserted_doc = url_repo.insert.call_args[0][0]
        assert inserted_doc["expire_after"] is not None

    @pytest.mark.asyncio
    async def test_create_past_expire_after_raises_validation_error(self):
        url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache = make_repos()
        svc = make_service(
            url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache
        )

        blocked_url_repo.get_patterns.return_value = []

        from schemas.dto.requests.url import CreateUrlRequest

        past_ts = 1000000  # very old timestamp
        req = CreateUrlRequest(long_url="https://example.com", expire_after=past_ts)
        with pytest.raises(ValidationError):
            await svc.create(req, owner_id=USER_OID, client_ip="1.2.3.4")


# ─────────────────────────────────────────────────────────────────────────────
# TestUrlServiceUpdate
# ─────────────────────────────────────────────────────────────────────────────


class TestUrlServiceUpdate:
    @pytest.mark.asyncio
    async def test_update_changes_field_and_invalidates_cache(self):
        url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache = make_repos()
        svc = make_service(
            url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache
        )

        existing = make_url_v2_doc()
        url_repo.find_by_id.return_value = existing
        url_repo.update.return_value = True

        from schemas.dto.requests.url import UpdateUrlRequest

        req = UpdateUrlRequest(long_url="https://new-url.com")
        await svc.update(URL_OID, req, USER_OID)

        url_repo.update.assert_called_once()
        update_doc = url_repo.update.call_args[0][1]
        assert "$set" in update_doc
        assert "long_url" in update_doc["$set"]
        url_cache.invalidate.assert_called_once_with(ALIAS, SYSTEM_DEFAULT_DOMAIN)

    @pytest.mark.asyncio
    async def test_update_no_changes_returns_existing(self):
        url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache = make_repos()
        svc = make_service(
            url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache
        )

        existing = make_url_v2_doc()
        url_repo.find_by_id.return_value = existing

        from schemas.dto.requests.url import UpdateUrlRequest

        # Send same long_url — no actual change
        req = UpdateUrlRequest(long_url="https://example.com")
        await svc.update(URL_OID, req, USER_OID)

        url_repo.update.assert_not_called()
        url_cache.invalidate.assert_not_called()

    @pytest.mark.asyncio
    async def test_update_wrong_owner_raises_forbidden(self):
        url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache = make_repos()
        svc = make_service(
            url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache
        )

        existing = make_url_v2_doc(owner_id=USER_OID)
        url_repo.find_by_id.return_value = existing

        other_user = ObjectId("eeeeeeeeeeeeeeeeeeeeeeee")

        from schemas.dto.requests.url import UpdateUrlRequest

        req = UpdateUrlRequest(long_url="https://new-url.com")
        with pytest.raises(ForbiddenError):
            await svc.update(URL_OID, req, other_user)

    @pytest.mark.asyncio
    async def test_update_not_found_raises_not_found(self):
        url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache = make_repos()
        svc = make_service(
            url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache
        )

        url_repo.find_by_id.return_value = None

        from schemas.dto.requests.url import UpdateUrlRequest

        req = UpdateUrlRequest(long_url="https://new-url.com")
        with pytest.raises(NotFoundError):
            await svc.update(URL_OID, req, USER_OID)

    @pytest.mark.asyncio
    async def test_update_alias_conflict_raises_conflict(self):
        url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache = make_repos()
        svc = make_service(
            url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache
        )

        existing = make_url_v2_doc()
        url_repo.find_by_id.return_value = existing
        # New alias already exists in v2
        url_repo.check_alias_exists.return_value = True

        from schemas.dto.requests.url import UpdateUrlRequest

        req = UpdateUrlRequest(alias="taken")
        with pytest.raises(ConflictError):
            await svc.update(URL_OID, req, USER_OID)

    @pytest.mark.asyncio
    async def test_update_blocked_url_raises_forbidden(self):
        url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache = make_repos()
        svc = make_service(
            url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache
        )

        existing = make_url_v2_doc(status="BLOCKED")
        url_repo.find_by_id.return_value = existing

        from schemas.dto.requests.url import UpdateUrlRequest

        req = UpdateUrlRequest(long_url="https://new-url.com")
        with pytest.raises(ForbiddenError, match="Cannot modify a blocked URL"):
            await svc.update(URL_OID, req, USER_OID)

        url_repo.update.assert_not_called()
        url_cache.invalidate.assert_not_called()

    @pytest.mark.asyncio
    async def test_update_blocked_url_status_change_raises_forbidden(self):
        url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache = make_repos()
        svc = make_service(
            url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache
        )

        existing = make_url_v2_doc(status="BLOCKED")
        url_repo.find_by_id.return_value = existing

        from schemas.dto.requests.url import UpdateUrlRequest

        req = UpdateUrlRequest(status="ACTIVE")
        with pytest.raises(ForbiddenError, match="Cannot modify a blocked URL"):
            await svc.update(URL_OID, req, USER_OID)

        url_repo.update.assert_not_called()
        url_cache.invalidate.assert_not_called()

    # ── Domain move (Part C) ─────────────────────────────────────────────────

    @pytest.mark.asyncio
    async def test_update_domain_move_invalidates_both_cache_keys(self):
        """Moving a URL between domains must clear the old AND new cache keys
        so a worker that populated the new key during the rename can't serve
        stale data."""
        url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache = make_repos()
        svc = make_service(
            url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache
        )

        existing = make_url_v2_doc(domain="spoo.me")
        url_repo.find_by_id.return_value = existing
        url_repo.update.return_value = True
        # Alias is free on the target tenant.
        url_repo.check_alias_exists.return_value = False
        legacy_repo.check_exists.return_value = False

        from schemas.dto.requests.url import UpdateUrlRequest

        req = UpdateUrlRequest(domain="links.acme.com")
        await svc.update(URL_OID, req, USER_OID)

        update_doc = url_repo.update.call_args[0][1]
        assert update_doc["$set"]["domain"] == "links.acme.com"
        # Both keys cleared — order doesn't matter, just both calls happened.
        invalidated = {tuple(c.args) for c in url_cache.invalidate.await_args_list}
        assert (ALIAS, "spoo.me") in invalidated
        assert (ALIAS, "links.acme.com") in invalidated

    @pytest.mark.asyncio
    async def test_update_domain_unchanged_is_noop(self):
        """`domain` set to the URL's current value shouldn't trigger a write."""
        url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache = make_repos()
        svc = make_service(
            url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache
        )

        existing = make_url_v2_doc(domain="links.acme.com")
        url_repo.find_by_id.return_value = existing

        from schemas.dto.requests.url import UpdateUrlRequest

        req = UpdateUrlRequest(domain="links.acme.com")
        await svc.update(URL_OID, req, USER_OID)

        url_repo.update.assert_not_called()

    @pytest.mark.asyncio
    async def test_update_domain_null_moves_to_system_default(self):
        """Passing `domain=null` moves the URL back to the system default."""
        url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache = make_repos()
        svc = make_service(
            url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache
        )

        existing = make_url_v2_doc(domain="links.acme.com")
        url_repo.find_by_id.return_value = existing
        url_repo.update.return_value = True
        url_repo.check_alias_exists.return_value = False
        legacy_repo.check_exists.return_value = False

        from schemas.dto.requests.url import UpdateUrlRequest

        # `UpdateUrlRequest(domain=None)` populates model_fields_set via the
        # constructor signature; using model_validate keeps it explicit that
        # we're sending a "clear to default" intent vs. an omitted field.
        req = UpdateUrlRequest.model_validate({"domain": None})
        await svc.update(URL_OID, req, USER_OID)

        update_doc = url_repo.update.call_args[0][1]
        assert update_doc["$set"]["domain"] == SYSTEM_DEFAULT_DOMAIN

    @pytest.mark.asyncio
    async def test_update_domain_alias_collision_on_target_raises_conflict(self):
        """An alias that's taken on the target domain blocks the move with a
        409, even if it's free on the source."""
        url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache = make_repos()
        svc = make_service(
            url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache
        )

        existing = make_url_v2_doc(domain="spoo.me")
        url_repo.find_by_id.return_value = existing
        # Target domain already has this alias.
        url_repo.check_alias_exists.return_value = True

        from schemas.dto.requests.url import UpdateUrlRequest

        req = UpdateUrlRequest(domain="links.acme.com")
        with pytest.raises(ConflictError, match="is already in use on"):
            await svc.update(URL_OID, req, USER_OID)

        url_repo.update.assert_not_called()

    @pytest.mark.asyncio
    async def test_update_alias_and_domain_together_checks_target_combo(self):
        """When both fields change in one request, the alias collision check
        must scope to the *target* domain — not the source."""
        url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache = make_repos()
        svc = make_service(
            url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache
        )

        existing = make_url_v2_doc(alias=ALIAS, domain="spoo.me")
        url_repo.find_by_id.return_value = existing
        url_repo.update.return_value = True
        url_repo.check_alias_exists.return_value = False
        legacy_repo.check_exists.return_value = False

        from schemas.dto.requests.url import UpdateUrlRequest

        req = UpdateUrlRequest(alias="newalias", domain="links.acme.com")
        await svc.update(URL_OID, req, USER_OID)

        # Pin the scope of the collision check — it should be the target
        # tenant, not the current one. Every call's domain arg must be the
        # target. (Domain handler short-circuits when ops["alias"] was set,
        # so only the alias handler should fire its check.)
        assert url_repo.check_alias_exists.await_count >= 1
        for call in url_repo.check_alias_exists.await_args_list:
            assert call.args[1] == "links.acme.com"

        update_doc = url_repo.update.call_args[0][1]["$set"]
        assert update_doc["alias"] == "newalias"
        assert update_doc["domain"] == "links.acme.com"


# ─────────────────────────────────────────────────────────────────────────────
# TestUrlServiceAutoReactivate
# ─────────────────────────────────────────────────────────────────────────────


class TestUrlServiceAutoReactivate:
    """Expired URLs should auto-reactivate when expiry conditions are updated."""

    @pytest.mark.asyncio
    async def test_raising_max_clicks_reactivates_expired_url(self):
        url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache = make_repos()
        svc = make_service(
            url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache
        )

        existing = UrlV2Doc.from_mongo(
            {
                "_id": URL_OID,
                "alias": ALIAS,
                "owner_id": USER_OID,
                "domain": SYSTEM_DEFAULT_DOMAIN,
                "created_at": datetime(2024, 1, 1, tzinfo=timezone.utc),
                "long_url": "https://example.com",
                "status": "EXPIRED",
                "max_clicks": 3,
                "total_clicks": 3,
                "private_stats": True,
            }
        )
        url_repo.find_by_id.return_value = existing
        url_repo.update.return_value = True

        from schemas.dto.requests.url import UpdateUrlRequest

        req = UpdateUrlRequest(max_clicks=10)
        await svc.update(URL_OID, req, USER_OID)

        update_doc = url_repo.update.call_args[0][1]
        assert update_doc["$set"]["status"] == "ACTIVE"
        assert update_doc["$set"]["max_clicks"] == 10

    @pytest.mark.asyncio
    async def test_clearing_max_clicks_reactivates_expired_url(self):
        url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache = make_repos()
        svc = make_service(
            url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache
        )

        existing = UrlV2Doc.from_mongo(
            {
                "_id": URL_OID,
                "alias": ALIAS,
                "owner_id": USER_OID,
                "domain": SYSTEM_DEFAULT_DOMAIN,
                "created_at": datetime(2024, 1, 1, tzinfo=timezone.utc),
                "long_url": "https://example.com",
                "status": "EXPIRED",
                "max_clicks": 3,
                "total_clicks": 3,
                "private_stats": True,
            }
        )
        url_repo.find_by_id.return_value = existing
        url_repo.update.return_value = True

        from schemas.dto.requests.url import UpdateUrlRequest

        req = UpdateUrlRequest(max_clicks=0)
        await svc.update(URL_OID, req, USER_OID)

        update_doc = url_repo.update.call_args[0][1]
        assert update_doc["$set"]["status"] == "ACTIVE"
        assert update_doc["$set"]["max_clicks"] is None

    @pytest.mark.asyncio
    async def test_extending_expire_after_reactivates_expired_url(self):
        url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache = make_repos()
        svc = make_service(
            url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache
        )

        existing = UrlV2Doc.from_mongo(
            {
                "_id": URL_OID,
                "alias": ALIAS,
                "owner_id": USER_OID,
                "domain": SYSTEM_DEFAULT_DOMAIN,
                "created_at": datetime(2024, 1, 1, tzinfo=timezone.utc),
                "long_url": "https://example.com",
                "status": "EXPIRED",
                "expire_after": datetime(2024, 6, 1, tzinfo=timezone.utc),
                "private_stats": True,
            }
        )
        url_repo.find_by_id.return_value = existing
        url_repo.update.return_value = True

        from schemas.dto.requests.url import UpdateUrlRequest

        req = UpdateUrlRequest(expire_after="2030-01-01T00:00:00Z")
        await svc.update(URL_OID, req, USER_OID)

        update_doc = url_repo.update.call_args[0][1]
        assert update_doc["$set"]["status"] == "ACTIVE"

    @pytest.mark.asyncio
    async def test_explicit_status_overrides_auto_reactivate(self):
        url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache = make_repos()
        svc = make_service(
            url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache
        )

        existing = UrlV2Doc.from_mongo(
            {
                "_id": URL_OID,
                "alias": ALIAS,
                "owner_id": USER_OID,
                "domain": SYSTEM_DEFAULT_DOMAIN,
                "created_at": datetime(2024, 1, 1, tzinfo=timezone.utc),
                "long_url": "https://example.com",
                "status": "EXPIRED",
                "max_clicks": 3,
                "total_clicks": 3,
                "private_stats": True,
            }
        )
        url_repo.find_by_id.return_value = existing
        url_repo.update.return_value = True

        from schemas.dto.requests.url import UpdateUrlRequest

        req = UpdateUrlRequest(max_clicks=10, status="INACTIVE")
        await svc.update(URL_OID, req, USER_OID)

        update_doc = url_repo.update.call_args[0][1]
        assert update_doc["$set"]["status"] == "INACTIVE"

    @pytest.mark.asyncio
    async def test_no_reactivate_when_max_clicks_still_exceeded(self):
        url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache = make_repos()
        svc = make_service(
            url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache
        )

        existing = UrlV2Doc.from_mongo(
            {
                "_id": URL_OID,
                "alias": ALIAS,
                "owner_id": USER_OID,
                "domain": SYSTEM_DEFAULT_DOMAIN,
                "created_at": datetime(2024, 1, 1, tzinfo=timezone.utc),
                "long_url": "https://example.com",
                "status": "EXPIRED",
                "max_clicks": 3,
                "total_clicks": 5,
                "private_stats": True,
            }
        )
        url_repo.find_by_id.return_value = existing
        url_repo.update.return_value = True

        from schemas.dto.requests.url import UpdateUrlRequest

        # Raising to 4 still below total_clicks of 5
        req = UpdateUrlRequest(max_clicks=4)
        await svc.update(URL_OID, req, USER_OID)

        update_doc = url_repo.update.call_args[0][1]
        assert "status" not in update_doc["$set"]


# ─────────────────────────────────────────────────────────────────────────────
# TestUrlServiceDelete
# ─────────────────────────────────────────────────────────────────────────────


class TestUrlServiceDelete:
    @pytest.mark.asyncio
    async def test_delete_success_invalidates_cache(self):
        url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache = make_repos()
        svc = make_service(
            url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache
        )

        existing = make_url_v2_doc()
        url_repo.find_by_id.return_value = existing
        url_repo.delete.return_value = True

        await svc.delete(URL_OID, USER_OID)

        url_repo.delete.assert_called_once_with(URL_OID)
        url_cache.invalidate.assert_called_once_with(ALIAS, SYSTEM_DEFAULT_DOMAIN)

    @pytest.mark.asyncio
    async def test_delete_wrong_owner_raises_forbidden(self):
        url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache = make_repos()
        svc = make_service(
            url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache
        )

        existing = make_url_v2_doc(owner_id=USER_OID)
        url_repo.find_by_id.return_value = existing

        other_user = ObjectId("eeeeeeeeeeeeeeeeeeeeeeee")
        with pytest.raises(ForbiddenError):
            await svc.delete(URL_OID, other_user)

        url_repo.delete.assert_not_called()

    @pytest.mark.asyncio
    async def test_delete_not_found_raises_not_found(self):
        url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache = make_repos()
        svc = make_service(
            url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache
        )

        url_repo.find_by_id.return_value = None

        with pytest.raises(NotFoundError):
            await svc.delete(URL_OID, USER_OID)

    @pytest.mark.asyncio
    async def test_delete_blocked_url_raises_forbidden(self):
        url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache = make_repos()
        svc = make_service(
            url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache
        )

        existing = make_url_v2_doc(status="BLOCKED")
        url_repo.find_by_id.return_value = existing

        with pytest.raises(ForbiddenError, match="Cannot delete a blocked URL"):
            await svc.delete(URL_OID, USER_OID)

        url_repo.delete.assert_not_called()
        url_cache.invalidate.assert_not_called()


# ─────────────────────────────────────────────────────────────────────────────
# TestCheckAliasAvailable
# ─────────────────────────────────────────────────────────────────────────────


class TestCheckAliasAvailable:
    @pytest.mark.asyncio
    async def test_available_when_not_in_v2_or_v1(self):
        url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache = make_repos()
        svc = make_service(
            url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache
        )

        url_repo.check_alias_exists.return_value = False
        legacy_repo.check_exists.return_value = False

        assert await svc.check_alias_available("newcode") is True

    @pytest.mark.asyncio
    async def test_unavailable_when_in_v2(self):
        url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache = make_repos()
        svc = make_service(
            url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache
        )

        url_repo.check_alias_exists.return_value = True

        assert await svc.check_alias_available("taken") is False
        legacy_repo.check_exists.assert_not_called()

    @pytest.mark.asyncio
    async def test_unavailable_when_in_v1(self):
        url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache = make_repos()
        svc = make_service(
            url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache
        )

        url_repo.check_alias_exists.return_value = False
        legacy_repo.check_exists.return_value = True

        assert await svc.check_alias_available("v1code") is False


# ─────────────────────────────────────────────────────────────────────────────
# TestUrlServiceUpdate
# ─────────────────────────────────────────────────────────────────────────────


class TestUrlServiceUpdateEdgeCases:
    @pytest.mark.asyncio
    async def test_update_not_found_raises(self):
        url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache = make_repos()
        svc = make_service(
            url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache
        )

        url_repo.find_by_id.return_value = None
        from schemas.dto.requests.url import UpdateUrlRequest

        with pytest.raises(NotFoundError):
            await svc.update(URL_OID, UpdateUrlRequest(), USER_OID)

    @pytest.mark.asyncio
    async def test_update_forbidden_raises(self):
        url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache = make_repos()
        svc = make_service(
            url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache
        )

        other_user = ObjectId("bbbbbbbbbbbbbbbbbbbbbbbb")
        url_repo.find_by_id.return_value = make_url_v2_doc(owner_id=other_user)
        from schemas.dto.requests.url import UpdateUrlRequest

        with pytest.raises(ForbiddenError):
            await svc.update(URL_OID, UpdateUrlRequest(), USER_OID)

    @pytest.mark.asyncio
    async def test_update_no_op_returns_existing(self):
        """When nothing changes, update() returns the existing doc without hitting the DB."""
        url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache = make_repos()
        svc = make_service(
            url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache
        )

        existing = make_url_v2_doc()
        url_repo.find_by_id.return_value = existing
        from schemas.dto.requests.url import UpdateUrlRequest

        # Empty request — nothing in model_fields_set, no long_url or alias given
        result = await svc.update(URL_OID, UpdateUrlRequest(), USER_OID)

        url_repo.update.assert_not_awaited()
        url_cache.invalidate.assert_not_awaited()
        assert result is existing

    @pytest.mark.asyncio
    async def test_update_clears_password_when_set_to_none(self):
        url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache = make_repos()
        svc = make_service(
            url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache
        )

        existing = make_url_v2_doc(password="oldhash")
        url_repo.find_by_id.return_value = existing
        url_repo.update.return_value = True
        url_cache.invalidate.return_value = None

        from schemas.dto.requests.url import UpdateUrlRequest

        req = UpdateUrlRequest(password=None)
        # Pydantic v2: explicitly passing password=None puts it in model_fields_set
        assert "password" in req.model_fields_set

        await svc.update(URL_OID, req, USER_OID)

        call_args = url_repo.update.call_args[0][1]
        assert call_args["$set"]["password"] is None

    @pytest.mark.asyncio
    async def test_update_clears_max_clicks_when_set_to_zero(self):
        url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache = make_repos()
        svc = make_service(
            url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache
        )

        existing = make_url_v2_doc(max_clicks=100)
        url_repo.find_by_id.return_value = existing
        url_repo.update.return_value = True

        from schemas.dto.requests.url import UpdateUrlRequest

        req = UpdateUrlRequest(max_clicks=0)
        await svc.update(URL_OID, req, USER_OID)

        call_args = url_repo.update.call_args[0][1]
        assert call_args["$set"]["max_clicks"] is None

    @pytest.mark.asyncio
    async def test_update_clears_expire_after_when_set_to_none(self):
        url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache = make_repos()
        svc = make_service(
            url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache
        )

        existing = make_url_v2_doc(
            expire_after=datetime(2030, 1, 1, tzinfo=timezone.utc)
        )
        url_repo.find_by_id.return_value = existing
        url_repo.update.return_value = True

        from schemas.dto.requests.url import UpdateUrlRequest

        req = UpdateUrlRequest(expire_after=None)
        await svc.update(URL_OID, req, USER_OID)

        call_args = url_repo.update.call_args[0][1]
        assert call_args["$set"]["expire_after"] is None

    @pytest.mark.asyncio
    async def test_update_alias_conflict_raises(self):
        url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache = make_repos()
        svc = make_service(
            url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache
        )

        existing = make_url_v2_doc(alias="old123")
        url_repo.find_by_id.return_value = existing
        # alias is taken
        url_repo.check_alias_exists.return_value = True
        legacy_repo.check_exists.return_value = False

        from schemas.dto.requests.url import UpdateUrlRequest

        req = UpdateUrlRequest(alias="newcode")
        with pytest.raises(ConflictError):
            await svc.update(URL_OID, req, USER_OID)

    @pytest.mark.asyncio
    async def test_update_changes_block_bots(self):
        url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache = make_repos()
        svc = make_service(
            url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache
        )

        existing = make_url_v2_doc(block_bots=False)
        url_repo.find_by_id.return_value = existing
        url_repo.update.return_value = True

        from schemas.dto.requests.url import UpdateUrlRequest

        req = UpdateUrlRequest(block_bots=True)
        await svc.update(URL_OID, req, USER_OID)

        call_args = url_repo.update.call_args[0][1]
        assert call_args["$set"]["block_bots"] is True


# ─────────────────────────────────────────────────────────────────────────────
# TestUrlServiceListByOwner
# ─────────────────────────────────────────────────────────────────────────────


class TestUrlServiceListByOwner:
    @pytest.mark.asyncio
    async def test_list_no_filter_returns_pagination(self):
        url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache = make_repos()
        svc = make_service(
            url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache
        )

        url_repo.count_by_query.return_value = 1
        url_repo.find_by_owner.return_value = [make_url_v2_doc()]

        from schemas.dto.requests.url import ListUrlsQuery

        result = await svc.list_by_owner(USER_OID, ListUrlsQuery())

        assert result["total"] == 1
        assert result["page"] == 1
        assert len(result["items"]) == 1
        assert result["hasNext"] is False

    @pytest.mark.asyncio
    async def test_list_with_status_filter(self):
        url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache = make_repos()
        svc = make_service(
            url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache
        )

        url_repo.count_by_query.return_value = 0
        url_repo.find_by_owner.return_value = []

        from schemas.dto.requests.url import ListUrlsQuery

        q = ListUrlsQuery(filter='{"status": "INACTIVE"}')
        await svc.list_by_owner(USER_OID, q)

        call_query = url_repo.count_by_query.call_args[0][0]
        assert call_query.get("status") == "INACTIVE"

    @pytest.mark.asyncio
    async def test_list_with_search_filter(self):
        url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache = make_repos()
        svc = make_service(
            url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache
        )

        url_repo.count_by_query.return_value = 0
        url_repo.find_by_owner.return_value = []

        from schemas.dto.requests.url import ListUrlsQuery

        q = ListUrlsQuery(filter='{"search": "example"}')
        await svc.list_by_owner(USER_OID, q)

        call_query = url_repo.count_by_query.call_args[0][0]
        assert "$or" in call_query

    @pytest.mark.asyncio
    async def test_list_with_password_set_filter(self):
        url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache = make_repos()
        svc = make_service(
            url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache
        )

        url_repo.count_by_query.return_value = 0
        url_repo.find_by_owner.return_value = []

        from schemas.dto.requests.url import ListUrlsQuery

        q = ListUrlsQuery(filter='{"passwordSet": true}')
        await svc.list_by_owner(USER_OID, q)

        call_query = url_repo.count_by_query.call_args[0][0]
        assert call_query.get("password") == {"$ne": None}

    @pytest.mark.asyncio
    async def test_list_with_max_clicks_set_false_filter(self):
        url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache = make_repos()
        svc = make_service(
            url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache
        )

        url_repo.count_by_query.return_value = 0
        url_repo.find_by_owner.return_value = []

        from schemas.dto.requests.url import ListUrlsQuery

        q = ListUrlsQuery(filter='{"maxClicksSet": false}')
        await svc.list_by_owner(USER_OID, q)

        call_query = url_repo.count_by_query.call_args[0][0]
        assert call_query.get("max_clicks") is None

    @pytest.mark.asyncio
    async def test_list_has_next_when_more_pages(self):
        url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache = make_repos()
        svc = make_service(
            url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache
        )

        url_repo.count_by_query.return_value = 50
        url_repo.find_by_owner.return_value = [make_url_v2_doc()] * 20

        from schemas.dto.requests.url import ListUrlsQuery

        result = await svc.list_by_owner(USER_OID, ListUrlsQuery(pageSize=20))

        assert result["hasNext"] is True
        assert result["total"] == 50


# ─────────────────────────────────────────────────────────────────────────────
# TestUrlServiceCreateOnCustomDomain
# ─────────────────────────────────────────────────────────────────────────────


class TestUrlServiceCreateOnCustomDomain:
    """create(..., domain=) writes the doc on the right tenant and routes
    alias-availability checks through the right namespace."""

    @pytest.mark.asyncio
    async def test_create_uses_provided_domain_for_doc_and_alias_check(self):
        from schemas.dto.requests.url import CreateUrlRequest

        url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache = make_repos()
        svc = make_service(
            url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache
        )

        url_repo.check_alias_exists = AsyncMock(return_value=False)
        url_repo.insert = AsyncMock(return_value=ObjectId())
        blocked_url_repo.get_patterns = AsyncMock(return_value=[])

        req = CreateUrlRequest(
            url="https://example.com/x",
            alias="myalias",
        )

        await svc.create(req, USER_OID, "1.2.3.4", domain="links.acme.com")

        # Alias-availability scoped to custom domain — and only that namespace
        # (no legacy fallback check).
        url_repo.check_alias_exists.assert_awaited_once_with(
            "myalias", "links.acme.com"
        )
        legacy_repo.check_exists.assert_not_called()

        # Doc inserted carries the custom domain.
        inserted = url_repo.insert.call_args[0][0]
        assert inserted["domain"] == "links.acme.com"

    @pytest.mark.asyncio
    async def test_create_auto_generates_alias_against_custom_domain(self):
        # Regression guard: previously _generate_unique_alias() probed the
        # system default namespace regardless of which tenant the URL was
        # being created on. With the domain= kwarg threaded through, the
        # candidate must be checked against the custom domain.
        from schemas.dto.requests.url import CreateUrlRequest

        url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache = make_repos()
        svc = make_service(
            url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache
        )

        url_repo.check_alias_exists = AsyncMock(return_value=False)
        url_repo.insert = AsyncMock(return_value=ObjectId())
        blocked_url_repo.get_patterns = AsyncMock(return_value=[])

        # No alias provided → service auto-generates one.
        req = CreateUrlRequest(url="https://example.com/auto-alias")

        await svc.create(req, USER_OID, "1.2.3.4", domain="links.acme.com")

        # The probe was scoped to the custom domain, never the system default.
        url_repo.check_alias_exists.assert_awaited_once()
        _, probed_domain = url_repo.check_alias_exists.call_args.args
        assert probed_domain == "links.acme.com"

        # Persisted doc lands on the custom tenant.
        inserted = url_repo.insert.call_args[0][0]
        assert inserted["domain"] == "links.acme.com"

    @pytest.mark.asyncio
    async def test_create_with_no_domain_uses_system_default(self):
        from schemas.dto.requests.url import CreateUrlRequest

        url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache = make_repos()
        svc = make_service(
            url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache
        )

        url_repo.check_alias_exists = AsyncMock(return_value=False)
        legacy_repo.check_exists = AsyncMock(return_value=False)
        url_repo.insert = AsyncMock(return_value=ObjectId())
        blocked_url_repo.get_patterns = AsyncMock(return_value=[])

        req = CreateUrlRequest(url="https://example.com/x", alias="mine")

        await svc.create(req, USER_OID, "1.2.3.4")

        # System default uses both v2 + legacy alias check.
        url_repo.check_alias_exists.assert_awaited_once_with(
            "mine", SYSTEM_DEFAULT_DOMAIN
        )
        legacy_repo.check_exists.assert_awaited_once_with("mine")
        inserted = url_repo.insert.call_args[0][0]
        assert inserted["domain"] == SYSTEM_DEFAULT_DOMAIN


# ─────────────────────────────────────────────────────────────────────────────
# TestUrlServiceBulkDelete
# ─────────────────────────────────────────────────────────────────────────────


class TestUrlServiceBulkDelete:
    @pytest.mark.asyncio
    async def test_bulk_delete_refuses_system_default(self):
        from errors import ValidationError

        url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache = make_repos()
        svc = make_service(
            url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache
        )
        with pytest.raises(ValidationError):
            await svc.delete_all_by_domain(USER_OID, SYSTEM_DEFAULT_DOMAIN)
        url_repo.delete_many_by_owner_and_domain.assert_not_called()

    @pytest.mark.asyncio
    async def test_bulk_delete_zero_match_returns_zero(self):
        url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache = make_repos()
        url_repo.list_aliases_by_owner_and_domain = AsyncMock(return_value=[])
        svc = make_service(
            url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache
        )
        count = await svc.delete_all_by_domain(USER_OID, "links.acme.com")
        assert count == 0
        url_repo.delete_many_by_owner_and_domain.assert_not_called()
        url_cache.invalidate_many.assert_not_called()

    @pytest.mark.asyncio
    async def test_bulk_delete_invalidates_cache_after_delete(self):
        url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache = make_repos()
        url_repo.list_aliases_by_owner_and_domain = AsyncMock(
            return_value=["a", "b", "c"]
        )
        url_repo.delete_many_by_owner_and_domain = AsyncMock(return_value=3)
        svc = make_service(
            url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache
        )

        count = await svc.delete_all_by_domain(USER_OID, "links.acme.com")

        assert count == 3
        url_repo.delete_many_by_owner_and_domain.assert_awaited_once_with(
            USER_OID, "links.acme.com"
        )
        url_cache.invalidate_many.assert_awaited_once_with(
            ["a", "b", "c"], "links.acme.com"
        )


# ─────────────────────────────────────────────────────────────────────────────
# TestUrlServiceListByOwnerDomainFilter
# ─────────────────────────────────────────────────────────────────────────────


class TestUrlServiceListByOwnerDomainFilter:
    @pytest.mark.asyncio
    async def test_list_with_domain_filter_passes_to_query(self):
        from schemas.dto.requests.url import ListUrlsQuery

        url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache = make_repos()
        svc = make_service(
            url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache
        )

        url_repo.count_by_query.return_value = 0
        url_repo.find_by_owner.return_value = []

        q = ListUrlsQuery(domain="links.acme.com")
        await svc.list_by_owner(USER_OID, q)

        call_query = url_repo.count_by_query.call_args[0][0]
        assert call_query.get("domain") == "links.acme.com"

    @pytest.mark.asyncio
    async def test_list_without_domain_filter_omits_field(self):
        from schemas.dto.requests.url import ListUrlsQuery

        url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache = make_repos()
        svc = make_service(
            url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache
        )

        url_repo.count_by_query.return_value = 0
        url_repo.find_by_owner.return_value = []

        q = ListUrlsQuery()
        await svc.list_by_owner(USER_OID, q)

        call_query = url_repo.count_by_query.call_args[0][0]
        assert "domain" not in call_query


# ─────────────────────────────────────────────────────────────────────────────
# _v2_doc_to_cache — meta_tags mapping
# ─────────────────────────────────────────────────────────────────────────────


class TestV2DocToCacheMetaTags:
    def test_carries_meta_tags(self):
        from services.url_service import _v2_doc_to_cache

        doc = make_url_v2_doc(
            meta_tags={
                "title": "T",
                "description": "D",
                "image": "https://x.com/i.png",
                "color": "#112233",
            }
        )
        d = _v2_doc_to_cache(doc)
        assert (d.meta_title, d.meta_description, d.meta_image, d.meta_color) == (
            "T",
            "D",
            "https://x.com/i.png",
            "#112233",
        )
        assert d.meta_image_width is None
        assert d.meta_image_height is None

    def test_no_meta_tags_maps_none(self):
        from services.url_service import _v2_doc_to_cache

        d = _v2_doc_to_cache(make_url_v2_doc())
        assert d.meta_title is None
        assert d.meta_description is None
        assert d.meta_image is None
        assert d.meta_color is None


# ─────────────────────────────────────────────────────────────────────────────
# meta_tags — update handler + abuse validation
# ─────────────────────────────────────────────────────────────────────────────


def _meta_req(**meta):
    from schemas.dto.requests.url import MetaTagsRequest, UpdateUrlRequest

    if meta.get("meta_tags") is None and "meta_tags" in meta:
        return UpdateUrlRequest(meta_tags=None)
    return UpdateUrlRequest(meta_tags=MetaTagsRequest(**meta))


def _mock_meta_service() -> AsyncMock:
    """Service mock for _handle_meta_tags: image resolution passes through."""
    svc = AsyncMock()
    svc.resolve_meta_image = AsyncMock(side_effect=lambda meta, owner: (meta, None))
    return svc


class TestHandleMetaTags:
    @pytest.mark.asyncio
    async def test_absent_field_is_noop(self):
        from schemas.dto.requests.url import UpdateUrlRequest
        from services.url_service import _handle_meta_tags

        svc = AsyncMock()
        ops: dict = {}
        await _handle_meta_tags(
            UpdateUrlRequest(), make_url_v2_doc(meta_tags={"title": "T"}), ops, svc
        )
        assert ops == {}
        svc.validate_meta_tags.assert_not_called()

    @pytest.mark.asyncio
    async def test_null_clears_existing(self):
        from services.url_service import _handle_meta_tags

        svc = AsyncMock()
        ops: dict = {}
        await _handle_meta_tags(
            _meta_req(meta_tags=None),
            make_url_v2_doc(meta_tags={"title": "T"}),
            ops,
            svc,
        )
        assert ops == {"meta_tags": None}
        svc.validate_meta_tags.assert_not_called()

    @pytest.mark.asyncio
    async def test_null_on_link_without_meta_is_noop(self):
        from services.url_service import _handle_meta_tags

        svc = AsyncMock()
        ops: dict = {}
        await _handle_meta_tags(_meta_req(meta_tags=None), make_url_v2_doc(), ops, svc)
        assert ops == {}

    @pytest.mark.asyncio
    async def test_object_replaces_whole_and_stamps_updated_at(self):
        from services.url_service import _handle_meta_tags

        svc = _mock_meta_service()
        ops: dict = {}
        await _handle_meta_tags(
            _meta_req(title="New", color="#112233"), make_url_v2_doc(), ops, svc
        )
        written = ops["meta_tags"]
        assert written["title"] == "New"
        assert written["color"] == "#112233"
        assert written["description"] is None
        assert written["updated_at"] is not None
        svc.validate_meta_tags.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_validates_against_new_destination_when_long_url_changes(self):
        from services.url_service import _handle_meta_tags

        svc = _mock_meta_service()
        ops: dict = {"long_url": "https://new-destination.com"}
        await _handle_meta_tags(_meta_req(title="T"), make_url_v2_doc(), ops, svc)
        assert (
            svc.validate_meta_tags.call_args.kwargs["long_url"]
            == "https://new-destination.com"
        )


class TestValidateMetaTags:
    def _svc_with_patterns(self, patterns):
        url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache = make_repos()
        blocked_url_repo.get_patterns.return_value = patterns
        return make_service(
            url_repo, legacy_repo, emoji_repo, blocked_url_repo, url_cache
        )

    @pytest.mark.asyncio
    async def test_clean_content_passes(self):
        from schemas.dto.requests.url import MetaTagsRequest

        svc = self._svc_with_patterns(["evil-token"])
        await svc.validate_meta_tags(
            MetaTagsRequest(title="Nice launch"), long_url="https://example.com"
        )

    @pytest.mark.asyncio
    async def test_blocked_pattern_in_title_rejected(self):
        from schemas.dto.requests.url import MetaTagsRequest

        svc = self._svc_with_patterns(["evil-token"])
        with pytest.raises(ValidationError) as exc:
            await svc.validate_meta_tags(
                MetaTagsRequest(title="totally evil-token deal"),
                long_url="https://example.com",
            )
        assert exc.value.field == "meta_tags"

    @pytest.mark.asyncio
    async def test_blocked_pattern_in_image_rejected(self):
        from schemas.dto.requests.url import MetaTagsRequest

        svc = self._svc_with_patterns(["evil-token"])
        with pytest.raises(ValidationError):
            await svc.validate_meta_tags(
                MetaTagsRequest(title="ok", image="https://evil-token.com/x.png"),
                long_url="https://example.com",
            )

    @pytest.mark.asyncio
    async def test_destination_recheck_rejects_blocked_long_url(self):
        from schemas.dto.requests.url import MetaTagsRequest

        svc = self._svc_with_patterns(["evil-token"])
        with pytest.raises(ValidationError) as exc:
            await svc.validate_meta_tags(
                MetaTagsRequest(title="ok"), long_url="https://evil-token.com/login"
            )
        assert exc.value.field == "long_url"
