"""Worker telemetry loops: stream metrics + stale consumer cleanup.

StreamMetricsReporter emits a periodic ``click_stream_stats`` log line
(backlog + per-group pending/lag) — the pipeline's health signal, shipped
to Axiom via the existing container-logs → Vector path, and the thing to
alert on (lag growing = worker falling behind; alert BEFORE the buffer
fills and the sink starts falling back inline).

StaleConsumerJanitor deletes consumer names that are long-dead with
nothing pending — every worker restart registers fresh
``{group}-{host}-{pid}`` names and Redis keeps the old ones forever,
cluttering ``XINFO CONSUMERS``. Deleting a consumer with pending
messages would orphan its PEL entries, so only pending==0 names go.
"""

from __future__ import annotations

import asyncio
from typing import Any

from infrastructure.logging import get_logger

log = get_logger(__name__)

# A consumer idle > 30 min with nothing pending is a restart leftover:
# live consumers block-read every ~2s, so real idle times stay in seconds.
STALE_CONSUMER_IDLE_MS = 30 * 60 * 1000
CONSUMER_GC_INTERVAL_SECONDS = 15 * 60


class StreamMetricsReporter:
    def __init__(self, redis_client: Any, stream: str, interval_seconds: float) -> None:
        self._redis = redis_client
        self._stream = stream
        self._interval = interval_seconds

    async def run_forever(self) -> None:
        while True:
            try:
                await self.report_once()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                log.warning(
                    "click_stream_stats_failed",
                    stream=self._stream,
                    error=str(exc),
                    error_type=type(exc).__name__,
                )
            await asyncio.sleep(self._interval)

    async def report_once(self) -> None:
        backlog = await self._redis.xlen(self._stream)
        groups = await self._redis.xinfo_groups(self._stream)
        log.info(
            "click_stream_stats",
            stream=self._stream,
            backlog=backlog,
            groups=[
                {
                    "name": g.get("name"),
                    "pending": g.get("pending"),
                    "lag": g.get("lag"),
                }
                for g in groups
            ],
        )


class StaleConsumerJanitor:
    def __init__(
        self,
        redis_client: Any,
        stream: str,
        idle_threshold_ms: int = STALE_CONSUMER_IDLE_MS,
        interval_seconds: float = CONSUMER_GC_INTERVAL_SECONDS,
    ) -> None:
        self._redis = redis_client
        self._stream = stream
        self._idle_threshold_ms = idle_threshold_ms
        self._interval = interval_seconds

    async def run_forever(self) -> None:
        while True:
            try:
                await self.sweep_once()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                log.warning(
                    "stale_consumer_sweep_failed",
                    stream=self._stream,
                    error=str(exc),
                    error_type=type(exc).__name__,
                )
            await asyncio.sleep(self._interval)

    async def sweep_once(self) -> int:
        """Delete dead consumer names; returns how many were removed."""
        removed = 0
        for group in await self._redis.xinfo_groups(self._stream):
            group_name = group.get("name")
            for consumer in await self._redis.xinfo_consumers(self._stream, group_name):
                if (
                    consumer.get("pending", 0) == 0
                    and consumer.get("idle", 0) > self._idle_threshold_ms
                ):
                    await self._redis.xgroup_delconsumer(
                        self._stream, group_name, consumer["name"]
                    )
                    removed += 1
        if removed:
            log.info("stale_consumers_removed", stream=self._stream, removed=removed)
        return removed
