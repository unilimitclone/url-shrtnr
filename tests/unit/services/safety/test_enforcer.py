"""Unit tests for SafetyEnforcer."""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock

import pytest
from bson import ObjectId

from schemas.models.base import ANONYMOUS_OWNER_ID
from schemas.models.url import UrlV2Doc
from services.safety.enforcer import SafetyEnforcer


def _owned_doc(alias: str) -> UrlV2Doc:
    return UrlV2Doc(
        _id=ObjectId(),
        alias=alias,
        owner_id=ObjectId(),
        domain="spoo.me",
        created_at=datetime.now(timezone.utc),
        long_url="https://evil.com/kit",
    )


def _build(pairs, owned, blocked_count, *, events=None, edge_kv=None):
    url_repo = AsyncMock()
    url_repo.list_active_alias_domain_by_dest_host = AsyncMock(return_value=pairs)
    url_repo.list_active_owned_by_dest_host = AsyncMock(return_value=owned)
    url_repo.block_active_by_dest_host = AsyncMock(return_value=blocked_count)
    legacy_repo = AsyncMock()
    legacy_repo.count_by_dest_host = AsyncMock(return_value=2)
    emoji_repo = AsyncMock()
    emoji_repo.count_by_dest_host = AsyncMock(return_value=1)
    url_cache = AsyncMock()
    enforcer = SafetyEnforcer(
        url_repo,
        legacy_repo,
        emoji_repo,
        url_cache,
        events=events,
        edge_kv=edge_kv,
        system_default_domain="spoo.me",
    )
    return enforcer, url_repo, url_cache


class TestBlockHost:
    @pytest.mark.asyncio
    async def test_flips_invalidates_and_counts(self):
        pairs = [("abc", "spoo.me"), ("xyz", "spoo.me"), ("cus", "go.acme.com")]
        enforcer, url_repo, url_cache = _build(pairs, [], 3)

        result = await enforcer.block_host("evil.com", reason="test")

        url_repo.block_active_by_dest_host.assert_awaited_once_with("evil.com")
        # Redis eviction grouped per domain namespace.
        invalidated = {
            call.args[1]: call.args[0]
            for call in url_cache.invalidate_many.await_args_list
        }
        assert invalidated["spoo.me"] == ["abc", "xyz"]
        assert invalidated["go.acme.com"] == ["cus"]
        assert result.blocked_count == 3
        assert result.legacy_count == 3  # urls (2) + emojis (1)
        assert result.cache_invalidated == 3

    @pytest.mark.asyncio
    async def test_edge_purge_system_domain_only(self):
        edge_kv = AsyncMock()
        pairs = [("abc", "spoo.me"), ("cus", "go.acme.com")]
        enforcer, _, _ = _build(pairs, [], 2, edge_kv=edge_kv)

        await enforcer.block_host("evil.com", reason="test")

        edge_kv.bulk_delete.assert_awaited_once_with(["cache:spoo.me:abc"])

    @pytest.mark.asyncio
    async def test_link_blocked_emitted_for_owned_only(self):
        events = AsyncMock()
        owned = [_owned_doc("abc")]
        # The anonymous doc never even reaches the enforcer (repo filters),
        # but a doc with the sentinel owner must still be skipped safely.
        anon = _owned_doc("anon")
        anon.owner_id = ANONYMOUS_OWNER_ID
        enforcer, _, _ = _build([("abc", "spoo.me")], [*owned, anon], 1, events=events)

        await enforcer.block_host("evil.com", reason="phishing kit")

        assert events.emit.await_count == 1
        event = events.emit.await_args.args[0]
        assert event.type == "link.blocked"
        assert event.data["reason"] == "phishing kit"
        assert event.data["link"]["status"] == "BLOCKED"

    @pytest.mark.asyncio
    async def test_idempotent_on_already_blocked(self):
        enforcer, _, url_cache = _build([], [], 0)
        result = await enforcer.block_host("evil.com", reason="again")
        assert result.blocked_count == 0
        url_cache.invalidate_many.assert_not_awaited()
