"""Tests for hot-URL promotion into the CF KV edge cache."""

from __future__ import annotations

import json
import random
from unittest.mock import AsyncMock, MagicMock

import pytest

from config import EdgeCacheSettings
from services.click.consumers.hotness import HotUrl
from services.edge_cache import (
    EdgeCacheEntry,
    PromoteToEdgeCacheAction,
    cache_key,
    promotion_skip_reason,
)
from tests.factories import make_url_cache

SYSTEM = "spoo.me"


def _hot(**overrides) -> HotUrl:
    kwargs = {
        "domain": SYSTEM,
        "short_code": "abc1234",
        "count": 50,
        "window_bucket": 12345,
    }
    kwargs.update(overrides)
    return HotUrl(**kwargs)


def _action(url_cache=None, kv=None, **overrides) -> PromoteToEdgeCacheAction:
    kwargs = {
        "system_domain": SYSTEM,
        "ttl_seconds": 300,
        "ttl_jitter_ratio": 0.2,
        "rng": random.Random(42),
    }
    kwargs.update(overrides)
    return PromoteToEdgeCacheAction(
        url_cache or MagicMock(), kv or MagicMock(), **kwargs
    )


class TestEligibility:
    def test_plain_active_url_is_eligible(self):
        url = make_url_cache()
        assert promotion_skip_reason(url, SYSTEM, SYSTEM) is None

    @pytest.mark.parametrize(
        ("overrides", "expected"),
        [
            ({"password_hash": "$argon2id$fake"}, "password_protected"),
            ({"max_clicks": 100}, "max_clicks"),
            ({"block_bots": True}, "block_bots"),
            ({"expiration_time": 1_900_000_000}, "has_expiration"),
            ({"url_status": "BLOCKED"}, "not_active"),
            ({"url_status": "EXPIRED"}, "not_active"),
            ({"url_status": "INACTIVE"}, "not_active"),
        ],
    )
    def test_restricted_urls_are_skipped(self, overrides, expected):
        url = make_url_cache(**overrides)
        assert promotion_skip_reason(url, SYSTEM, SYSTEM) == expected

    def test_tenant_domain_is_skipped(self):
        url = make_url_cache(domain="links.acme.com")
        reason = promotion_skip_reason(url, "links.acme.com", SYSTEM)
        assert reason == "non_system_domain"

    def test_v1_urls_are_eligible(self):
        """Legacy URLs cache with domain=system default → same rules apply."""
        url = make_url_cache(schema_version="v1", owner_id=None)
        assert promotion_skip_reason(url, SYSTEM, SYSTEM) is None


class TestPromoteAction:
    async def test_eligible_url_is_promoted(self):
        url_cache = MagicMock()
        url_cache.get = AsyncMock(
            return_value=make_url_cache(long_url="https://example.com/dest")
        )
        kv = MagicMock()
        kv.put = AsyncMock(return_value=True)

        await _action(url_cache, kv).on_hot(_hot())

        kv.put.assert_awaited_once()
        args = kv.put.await_args
        assert args.args[0] == cache_key(SYSTEM, "abc1234")
        entry = json.loads(args.args[1])
        assert entry == {
            "type": "redirect",
            "url": "https://example.com/dest",
            "status": 302,
        }
        # jitter keeps TTL within ±20% of 300s
        assert 240 <= args.kwargs["expiration_ttl"] <= 360

    async def test_cache_miss_skips_without_kv_write(self):
        url_cache = MagicMock()
        url_cache.get = AsyncMock(return_value=None)
        kv = MagicMock()
        kv.put = AsyncMock()

        await _action(url_cache, kv).on_hot(_hot())

        kv.put.assert_not_awaited()

    async def test_ineligible_url_skips_without_kv_write(self):
        url_cache = MagicMock()
        url_cache.get = AsyncMock(return_value=make_url_cache(block_bots=True))
        kv = MagicMock()
        kv.put = AsyncMock()

        await _action(url_cache, kv).on_hot(_hot())

        kv.put.assert_not_awaited()

    async def test_kv_failure_never_raises(self):
        url_cache = MagicMock()
        url_cache.get = AsyncMock(return_value=make_url_cache())
        kv = MagicMock()
        kv.put = AsyncMock(return_value=False)

        await _action(url_cache, kv).on_hot(_hot())  # must not raise

    async def test_jitter_never_goes_below_kv_minimum(self):
        """CF KV rejects expiration_ttl < 60 — the floor must hold even
        with tiny configured TTLs."""
        url_cache = MagicMock()
        url_cache.get = AsyncMock(return_value=make_url_cache())
        kv = MagicMock()
        kv.put = AsyncMock(return_value=True)

        await _action(url_cache, kv, ttl_seconds=60, ttl_jitter_ratio=0.5).on_hot(
            _hot()
        )

        assert kv.put.await_args.kwargs["expiration_ttl"] >= 60


class TestEdgeCacheEntryContract:
    def test_wire_shape_is_pinned(self):
        """The JSON the Worker parses — field names are the contract."""
        entry = EdgeCacheEntry(url="https://example.com")
        assert json.loads(entry.model_dump_json()) == {
            "type": "redirect",
            "url": "https://example.com",
            "status": 302,
        }


class TestEdgeCacheSettings:
    def test_disabled_unless_all_three_set(self):
        assert EdgeCacheSettings(_env_file=None).enabled is False
        assert (
            EdgeCacheSettings(
                _env_file=None, cf_account_id="a", cf_api_token="t"
            ).enabled
            is False
        )

    def test_enabled_when_fully_configured(self):
        settings = EdgeCacheSettings(
            _env_file=None,
            cf_account_id="a",
            cf_api_token="t",
            kv_namespace_id="ns",
        )
        assert settings.enabled is True
