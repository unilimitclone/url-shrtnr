"""Tests for the stream history sweeper."""

from __future__ import annotations

from unittest.mock import AsyncMock

from workers.trimmer import StreamTrimmer, _id_sort_key


def _trimmer(redis) -> StreamTrimmer:
    return StreamTrimmer(redis, stream="events:clicks", interval_seconds=60)


def _redis(groups, pending_by_group) -> AsyncMock:
    redis = AsyncMock()
    redis.xinfo_groups.return_value = groups
    redis.xpending.side_effect = lambda _s, g: pending_by_group[g]
    redis.xtrim.return_value = 0
    return redis


class TestIdSortKey:
    def test_numeric_not_lexical(self):
        """"999-0" must sort BELOW "1000-0" (lexical order says otherwise)."""
        assert _id_sort_key("999-0") < _id_sort_key("1000-0")
        assert _id_sort_key("100-2") > _id_sort_key("100-1")

    def test_missing_sequence_defaults_to_zero(self):
        assert _id_sort_key("100") == (100, 0)


class TestSafeFloor:
    async def test_no_groups_means_no_trimming(self):
        redis = AsyncMock()
        redis.xinfo_groups.return_value = []
        assert await _trimmer(redis).safe_floor() is None

    async def test_fully_consumed_groups_trim_through_last_delivered(self):
        redis = _redis(
            groups=[
                {"name": "stats", "last-delivered-id": "500-3"},
                {"name": "hotness", "last-delivered-id": "500-3"},
            ],
            pending_by_group={
                "stats": {"pending": 0, "min": None, "max": None},
                "hotness": {"pending": 0, "min": None, "max": None},
            },
        )
        # everything ≤ 500-3 is acked → floor is the next id
        assert await _trimmer(redis).safe_floor() == "500-4"

    async def test_pending_entry_pins_the_floor(self):
        """An unacked message must survive trimming even if the other group
        is far ahead."""
        redis = _redis(
            groups=[
                {"name": "stats", "last-delivered-id": "900-0"},
                {"name": "hotness", "last-delivered-id": "900-0"},
            ],
            pending_by_group={
                "stats": {"pending": 2, "min": "450-1", "max": "460-0"},
                "hotness": {"pending": 0, "min": None, "max": None},
            },
        )
        assert await _trimmer(redis).safe_floor() == "450-1"

    async def test_lagging_group_pins_the_floor(self):
        """A group that has consumed less holds back trimming globally."""
        redis = _redis(
            groups=[
                {"name": "stats", "last-delivered-id": "1000-0"},
                {"name": "hotness", "last-delivered-id": "200-5"},
            ],
            pending_by_group={
                "stats": {"pending": 0, "min": None, "max": None},
                "hotness": {"pending": 0, "min": None, "max": None},
            },
        )
        assert await _trimmer(redis).safe_floor() == "200-6"

    async def test_numeric_comparison_across_groups(self):
        redis = _redis(
            groups=[
                {"name": "stats", "last-delivered-id": "999-0"},
                {"name": "hotness", "last-delivered-id": "1000-0"},
            ],
            pending_by_group={
                "stats": {"pending": 0, "min": None, "max": None},
                "hotness": {"pending": 0, "min": None, "max": None},
            },
        )
        assert await _trimmer(redis).safe_floor() == "999-1"


class TestTrimOnce:
    async def test_trims_with_exact_minid(self):
        redis = _redis(
            groups=[{"name": "stats", "last-delivered-id": "500-0"}],
            pending_by_group={"stats": {"pending": 0, "min": None, "max": None}},
        )
        redis.xtrim.return_value = 1234

        removed = await _trimmer(redis).trim_once()

        assert removed == 1234
        redis.xtrim.assert_awaited_once_with(
            "events:clicks", minid="500-1", approximate=False
        )

    async def test_no_groups_skips_trim(self):
        redis = AsyncMock()
        redis.xinfo_groups.return_value = []
        assert await _trimmer(redis).trim_once() == 0
        redis.xtrim.assert_not_awaited()
