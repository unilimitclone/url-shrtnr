"""Tests for worker telemetry loops."""

from __future__ import annotations

from unittest.mock import AsyncMock

from workers.telemetry import StaleConsumerJanitor, StreamMetricsReporter


def _redis_with_groups(groups, consumers_by_group=None) -> AsyncMock:
    redis = AsyncMock()
    redis.xlen.return_value = 42
    redis.xinfo_groups.return_value = groups
    if consumers_by_group is not None:
        redis.xinfo_consumers.side_effect = lambda _s, g: consumers_by_group[g]
    return redis


class TestStreamMetricsReporter:
    async def test_report_once_reads_backlog_and_groups(self):
        redis = _redis_with_groups([{"name": "stats", "pending": 3, "lag": 17}])
        reporter = StreamMetricsReporter(redis, "events:clicks", 30.0)

        await reporter.report_once()  # must not raise

        redis.xlen.assert_awaited_once_with("events:clicks")
        redis.xinfo_groups.assert_awaited_once_with("events:clicks")


class TestStaleConsumerJanitor:
    def _janitor(self, redis) -> StaleConsumerJanitor:
        return StaleConsumerJanitor(redis, "events:clicks", idle_threshold_ms=1000)

    async def test_removes_dead_idle_consumers(self):
        redis = _redis_with_groups(
            [{"name": "stats"}],
            {
                "stats": [
                    {"name": "stats-old-1", "pending": 0, "idle": 999_999},
                    {"name": "stats-live-2", "pending": 0, "idle": 50},
                ]
            },
        )
        removed = await self._janitor(redis).sweep_once()

        assert removed == 1
        redis.xgroup_delconsumer.assert_awaited_once_with(
            "events:clicks", "stats", "stats-old-1"
        )

    async def test_never_removes_consumers_with_pending(self):
        """Deleting a consumer with pending would orphan its PEL entries."""
        redis = _redis_with_groups(
            [{"name": "stats"}],
            {"stats": [{"name": "stats-dead", "pending": 2, "idle": 999_999}]},
        )
        removed = await self._janitor(redis).sweep_once()

        assert removed == 0
        redis.xgroup_delconsumer.assert_not_awaited()

    async def test_sweeps_all_groups(self):
        redis = _redis_with_groups(
            [{"name": "stats"}, {"name": "hotness"}],
            {
                "stats": [{"name": "s-old", "pending": 0, "idle": 999_999}],
                "hotness": [{"name": "h-old", "pending": 0, "idle": 999_999}],
            },
        )
        assert await self._janitor(redis).sweep_once() == 2
