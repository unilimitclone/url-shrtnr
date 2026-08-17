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


def _build(
    pairs,
    owned,
    blocked_count,
    *,
    legacy_ids=None,
    emoji_ids=None,
    events=None,
    edge_kv=None,
):
    url_repo = AsyncMock()
    url_repo.list_active_alias_domain_by_dest_host = AsyncMock(return_value=pairs)
    url_repo.list_active_owned_by_dest_host = AsyncMock(return_value=owned)
    url_repo.block_active_by_dest_host = AsyncMock(return_value=blocked_count)
    legacy_repo = AsyncMock()
    legacy_repo.list_unblocked_ids_by_dest_host = AsyncMock(
        return_value=legacy_ids or []
    )
    legacy_repo.block_by_dest_host = AsyncMock(return_value=len(legacy_ids or []))
    emoji_repo = AsyncMock()
    emoji_repo.list_unblocked_ids_by_dest_host = AsyncMock(return_value=emoji_ids or [])
    emoji_repo.block_by_dest_host = AsyncMock(return_value=len(emoji_ids or []))
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
    return enforcer, url_repo, url_cache, legacy_repo, emoji_repo


class TestBlockHost:
    @pytest.mark.asyncio
    async def test_flips_invalidates_and_counts(self):
        pairs = [("abc", "spoo.me"), ("xyz", "spoo.me"), ("cus", "go.acme.com")]
        enforcer, url_repo, url_cache, _, _ = _build(
            pairs, [], 3, legacy_ids=["old1", "old2"], emoji_ids=["🎉🎉"]
        )

        result = await enforcer.block_host("evil.com", reason="test")

        url_repo.block_active_by_dest_host.assert_awaited_once_with(
            "evil.com", reason="test"
        )
        # Redis eviction grouped per domain namespace; v1/emoji ids join
        # the system-domain namespace.
        invalidated = {
            call.args[1]: call.args[0]
            for call in url_cache.invalidate_many.await_args_list
        }
        assert invalidated["spoo.me"] == ["abc", "xyz", "old1", "old2", "🎉🎉"]
        assert invalidated["go.acme.com"] == ["cus"]
        assert result.blocked_count == 3
        assert result.legacy_count == 3  # urls (2) + emojis (1), now BLOCKED
        assert result.cache_invalidated == 6

    @pytest.mark.asyncio
    async def test_legacy_flip_carries_the_reason(self):
        """The audit trail is per-link on every collection — the reason
        must reach the v1/emoji flip, not just the v2 one."""
        enforcer, _, _, legacy_repo, emoji_repo = _build(
            [], [], 0, legacy_ids=["a"], emoji_ids=["⭐"]
        )

        await enforcer.block_host("evil.com", reason="phishing kit")

        legacy_repo.block_by_dest_host.assert_awaited_once_with(
            "evil.com", reason="phishing kit"
        )
        emoji_repo.block_by_dest_host.assert_awaited_once_with(
            "evil.com", reason="phishing kit"
        )

    @pytest.mark.asyncio
    async def test_emoji_eviction_uses_canonical_alias(self):
        """The cache keys emoji entries under the canonical VS16 form, so
        a legacy variant ``_id`` must be canonicalized before eviction."""
        variant = "⭐️"  # stored with VS16
        enforcer, _, url_cache, _, _ = _build([], [], 0, emoji_ids=[variant])

        await enforcer.block_host("evil.com", reason="test")

        evicted = url_cache.invalidate_many.await_args.args[0]
        assert evicted == ["⭐"]  # canonical, VS16 stripped

    @pytest.mark.asyncio
    async def test_edge_purge_system_domain_only(self):
        edge_kv = AsyncMock()
        pairs = [("abc", "spoo.me"), ("cus", "go.acme.com")]
        enforcer, _, _, _, _ = _build(
            pairs, [], 2, legacy_ids=["old1"], edge_kv=edge_kv
        )

        await enforcer.block_host("evil.com", reason="test")

        edge_kv.bulk_delete.assert_awaited_once_with(
            ["cache:spoo.me:abc", "cache:spoo.me:old1"]
        )

    @pytest.mark.asyncio
    async def test_link_blocked_emitted_for_owned_only(self):
        events = AsyncMock()
        owned = [_owned_doc("abc")]
        # The anonymous doc never even reaches the enforcer (repo filters),
        # but a doc with the sentinel owner must still be skipped safely.
        anon = _owned_doc("anon")
        anon.owner_id = ANONYMOUS_OWNER_ID
        enforcer, _, _, _, _ = _build(
            [("abc", "spoo.me")], [*owned, anon], 1, events=events
        )

        await enforcer.block_host("evil.com", reason="phishing kit")

        assert events.emit.await_count == 1
        event = events.emit.await_args.args[0]
        assert event.type == "link.blocked"
        assert event.data["reason"] == "phishing kit"
        assert event.data["link"]["status"] == "BLOCKED"

    @pytest.mark.asyncio
    async def test_idempotent_on_already_blocked(self):
        enforcer, _, url_cache, _, _ = _build([], [], 0)
        result = await enforcer.block_host("evil.com", reason="again")
        assert result.blocked_count == 0
        assert result.legacy_count == 0
        url_cache.invalidate_many.assert_not_awaited()
