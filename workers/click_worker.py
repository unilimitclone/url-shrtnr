"""Click event worker — consumes the click stream with FastStream.

Run with (compose does this):

    uv run uvicorn --factory workers.click_worker:create_app \
        --host 0.0.0.0 --port 8001

One process hosts every enabled consumer group. Per group, TWO FastStream
subscribers are registered against the same stream:

- **reader**  — normal ``XREADGROUP`` consumption of new messages.
- **claimer** — ``XAUTOCLAIM`` recovery (``min_idle_time``) of messages a
  dead/stuck consumer never acked. FastStream 0.7 makes these two modes
  mutually exclusive per subscriber, hence the pair. The claim path is
  fronted by :class:`ClaimDeadLetterGuard` so poison messages land in the
  DLQ after ``max_deliveries`` attempts instead of looping forever.

Both subscribers delegate to the same framework-free consumer class
(``StatsClickConsumer`` / ``HotUrlDetector``), so processing logic stays
identical regardless of which path delivered the message. Handler
exceptions leave the message pending (FastStream's default
``REJECT_ON_ERROR`` policy for group subscribers = no XACK), which is
what feeds the claimer.

Groups hosted by this process = ``CLICK_EVENTS_WORKER_GROUPS`` filtered by
feature toggles (``hotness`` also needs ``CLICK_EVENTS_HOTNESS_ENABLED``).
A future deployment can split groups across containers by setting
``CLICK_EVENTS_WORKER_GROUPS='["stats"]'`` etc. — no code change.

``GET /health`` (ASGI) pings the broker — wired as the container
healthcheck.
"""

from __future__ import annotations

import asyncio
import os
import socket
from dataclasses import dataclass, field
from typing import Any, Protocol

from dotenv import load_dotenv
from faststream.asgi import AsgiFastStream, make_ping_asgi
from faststream.redis import RedisBroker, StreamSub
from faststream.redis.annotations import Redis, RedisMessage
from pymongo.asynchronous.mongo_client import AsyncMongoClient

from config import AppSettings, ClickEventsSettings
from dependencies.wiring import build_click_service
from infrastructure.cache.redis_client import create_redis_client
from infrastructure.cache.url_cache import UrlCache
from infrastructure.geoip import GeoIPService
from infrastructure.logging import get_logger, setup_logging
from repositories.click_repository import ClickRepository
from repositories.legacy.emoji_url_repository import EmojiUrlRepository
from repositories.legacy.legacy_url_repository import LegacyUrlRepository
from repositories.url_repository import UrlRepository
from services.click.consumers import (
    HotUrlDetector,
    LogHotUrlAction,
    StatsClickConsumer,
)
from workers.dlq import ClaimDeadLetterGuard
from workers.trimmer import StreamTrimmer

log = get_logger(__name__)

# The worker's Mongo traffic is a fraction of the web app's — small pool.
_WORKER_MONGO_MAX_POOL = 16


class ClickConsumer(Protocol):
    """Contract every group's consumer class satisfies."""

    async def consume(self, payload: Any) -> None: ...


@dataclass
class _WorkerRuntime:
    """Connections and consumers built at startup, closed at shutdown."""

    mongo_client: AsyncMongoClient
    cache_redis: Any | None
    counter_redis: Any | None
    trim_redis: Any | None = None
    trim_task: asyncio.Task | None = None
    consumers: dict[str, ClickConsumer] = field(default_factory=dict)

    async def aclose(self) -> None:
        if self.trim_task is not None:
            self.trim_task.cancel()
        await self.mongo_client.close()
        if self.cache_redis is not None:
            await self.cache_redis.aclose()
        if self.counter_redis is not None:
            await self.counter_redis.aclose()
        if self.trim_redis is not None:
            await self.trim_redis.aclose()


def enabled_groups(ce: ClickEventsSettings) -> list[str]:
    """Groups this process should host: worker_groups ∩ feature toggles."""
    groups = []
    for group in ce.worker_groups:
        if group == "hotness" and not ce.hotness_enabled:
            continue
        groups.append(group)
    return groups


async def _build_runtime(settings: AppSettings, groups: list[str]) -> _WorkerRuntime:
    ce = settings.click_events
    mongo_client: AsyncMongoClient = AsyncMongoClient(
        settings.db.mongodb_uri,
        maxPoolSize=_WORKER_MONGO_MAX_POOL,
        minPoolSize=1,
    )
    db = mongo_client[settings.db.db_name]

    # Cache Redis is optional in the worker exactly as in the web app —
    # without it the URL cache degrades to no-ops (max-clicks expiry just
    # skips cache invalidation; resolve-side caching is the app's concern).
    cache_redis = None
    if settings.redis.redis_uri:
        cache_redis = await create_redis_client(settings.redis.redis_uri, label="cache")

    runtime = _WorkerRuntime(
        mongo_client=mongo_client,
        cache_redis=cache_redis,
        counter_redis=None,
    )

    if "stats" in groups:
        geoip = GeoIPService(settings.geoip_country_db, settings.geoip_city_db)
        url_cache = UrlCache(cache_redis, ttl_seconds=settings.redis.redis_ttl_seconds)
        runtime.consumers["stats"] = StatsClickConsumer(
            build_click_service(
                ClickRepository(db["clicks"]),
                UrlRepository(db["urlsV2"]),
                LegacyUrlRepository(db["urls"]),
                EmojiUrlRepository(db["emojis"]),
                geoip,
                url_cache,
            )
        )

    if "hotness" in groups:
        # Window counters live on the queue Redis (noeviction) — a separate
        # decode_responses client from the broker's internal bytes client.
        counter_redis = await create_redis_client(
            ce.queue_redis_uri, label="hotness-counters"
        )
        if counter_redis is None:
            await runtime.aclose()
            raise RuntimeError(
                "hotness group enabled but the queue Redis is unreachable"
            )
        runtime.counter_redis = counter_redis
        runtime.consumers["hotness"] = HotUrlDetector(
            counter_redis,
            threshold=ce.hot_threshold,
            window_seconds=ce.hot_window_seconds,
            actions=[LogHotUrlAction()],
        )

    if ce.trim_enabled:
        trim_redis = await create_redis_client(
            ce.queue_redis_uri, label="stream-trimmer"
        )
        if trim_redis is not None:
            runtime.trim_redis = trim_redis
            runtime.trim_task = asyncio.create_task(
                StreamTrimmer(
                    trim_redis, ce.stream, ce.trim_interval_seconds
                ).run_forever()
            )

    return runtime


def _register_group(
    broker: RedisBroker,
    ce: ClickEventsSettings,
    group: str,
    consumer_suffix: str,
    consumer_for: Any,
) -> None:
    """Register the reader + claimer subscriber pair for one group."""
    guard = ClaimDeadLetterGuard(
        stream=ce.stream,
        group=group,
        dlq_stream=ce.dlq_stream,
        max_deliveries=ce.max_deliveries,
    )

    async def reader(body: Any) -> None:
        await consumer_for(group).consume(body)

    reader.__name__ = f"{group}_reader"
    broker.subscriber(
        stream=StreamSub(
            ce.stream,
            group=group,
            consumer=f"{group}-{consumer_suffix}",
            max_records=ce.batch_size,
            polling_interval=ce.block_ms,
        )
    )(reader)

    async def claimer(body: Any, msg: RedisMessage, redis: Redis) -> None:
        message_id = _first_message_id(msg)
        if message_id and await guard.intercept(redis, message_id, body):
            return  # dead-lettered; normal return lets FastStream XACK
        await consumer_for(group).consume(body)

    claimer.__name__ = f"{group}_claimer"
    broker.subscriber(
        stream=StreamSub(
            ce.stream,
            group=group,
            consumer=f"{group}-{consumer_suffix}-claim",
            min_idle_time=ce.claim_idle_ms,
            polling_interval=ce.block_ms,
        )
    )(claimer)


def _first_message_id(msg: Any) -> str | None:
    ids = (getattr(msg, "raw_message", None) or {}).get("message_ids") or []
    if not ids:
        return None
    first = ids[0]
    return first.decode() if isinstance(first, bytes) else str(first)


def create_worker_app(settings: AppSettings | None = None) -> AsgiFastStream:
    """Build the worker application (separated from ``create_app`` for tests)."""
    if settings is None:
        settings = AppSettings()
    ce = settings.click_events

    if ce.sink != "stream" or not ce.queue_redis_uri:
        raise RuntimeError(
            "The click worker requires CLICK_EVENTS_SINK=stream and "
            "CLICK_EVENTS_QUEUE_REDIS_URI. Refusing to start so a "
            "misconfigured deployment fails loudly instead of idling."
        )

    groups = enabled_groups(ce)
    if not groups:
        raise RuntimeError(
            "No consumer groups enabled for this worker — check "
            "CLICK_EVENTS_WORKER_GROUPS and CLICK_EVENTS_HOTNESS_ENABLED."
        )

    broker = RedisBroker(ce.queue_redis_uri)
    runtime_holder: dict[str, _WorkerRuntime] = {}

    def consumer_for(group: str) -> ClickConsumer:
        runtime = runtime_holder.get("runtime")
        if runtime is None:  # pragma: no cover — startup hook always runs first
            raise RuntimeError("worker runtime not initialised")
        return runtime.consumers[group]

    consumer_suffix = f"{socket.gethostname()}-{os.getpid()}"
    for group in groups:
        _register_group(broker, ce, group, consumer_suffix, consumer_for)

    async def _startup() -> None:
        runtime_holder["runtime"] = await _build_runtime(settings, groups)
        log.info(
            "click_worker_started",
            stream=ce.stream,
            groups=groups,
            claim_idle_ms=ce.claim_idle_ms,
            max_deliveries=ce.max_deliveries,
        )

    async def _shutdown() -> None:
        runtime = runtime_holder.pop("runtime", None)
        if runtime is not None:
            await runtime.aclose()
        log.info("click_worker_stopped")

    return AsgiFastStream(
        broker,
        asgi_routes=[("/health", make_ping_asgi(broker, timeout=5.0))],
        on_startup=[_startup],
        on_shutdown=[_shutdown],
    )


def create_app() -> AsgiFastStream:
    """uvicorn --factory entrypoint.

    ``load_dotenv`` runs here (not at import time) so importing this module
    never mutates ``os.environ`` — pydantic-settings reads the .env file on
    its own; this call only covers non-settings ``os.environ`` readers, the
    same contract as ``main.py``.
    """
    load_dotenv()
    setup_logging()
    return create_worker_app()
