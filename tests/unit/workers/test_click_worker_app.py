"""Tests for the click worker application factory."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from config import AppSettings, ClickEventsSettings
from workers.click_worker import (
    _first_message_id,
    create_worker_app,
    enabled_groups,
)


def _settings(**ce_overrides) -> AppSettings:
    base = dict(sink="stream", queue_redis_uri="redis://localhost:6399/0")
    base.update(ce_overrides)
    settings = AppSettings()
    settings.click_events = ClickEventsSettings(**base)
    return settings


class TestEnabledGroups:
    def test_default_groups_without_hotness_flag(self):
        ce = ClickEventsSettings()
        assert enabled_groups(ce) == ["stats"]

    def test_hotness_included_when_enabled(self):
        ce = ClickEventsSettings(hotness_enabled=True)
        assert enabled_groups(ce) == ["stats", "hotness"]

    def test_worker_groups_subset_respected(self):
        ce = ClickEventsSettings(worker_groups=["hotness"], hotness_enabled=True)
        assert enabled_groups(ce) == ["hotness"]


class TestCreateWorkerApp:
    def test_refuses_inline_sink(self):
        settings = AppSettings()
        settings.click_events = ClickEventsSettings(sink="inline")
        with pytest.raises(RuntimeError, match="CLICK_EVENTS_SINK=stream"):
            create_worker_app(settings)

    def test_refuses_missing_queue_uri(self):
        settings = AppSettings()
        settings.click_events = ClickEventsSettings(sink="stream")
        with pytest.raises(RuntimeError, match="QUEUE_REDIS_URI"):
            create_worker_app(settings)

    def test_refuses_empty_group_selection(self):
        settings = _settings(worker_groups=["hotness"], hotness_enabled=False)
        with pytest.raises(RuntimeError, match="No consumer groups"):
            create_worker_app(settings)

    def test_registers_reader_and_claimer_per_group(self):
        settings = _settings(hotness_enabled=True)
        app = create_worker_app(settings)

        subscribers = app.brokers[0].subscribers
        # 2 groups x (reader + claimer)
        assert len(subscribers) == 4
        specs = [s.stream_sub for s in subscribers]
        by_consumer = {s.consumer: s for s in specs}
        readers = [s for s in specs if s.min_idle_time is None]
        claimers = [s for s in specs if s.min_idle_time is not None]
        assert len(readers) == 2
        assert len(claimers) == 2
        assert {s.group for s in specs} == {"stats", "hotness"}
        assert all(s.name == "events:clicks" for s in specs)
        assert all(c.endswith("-claim") for c in by_consumer if "-claim" in c)

    def test_stats_only_by_default(self):
        app = create_worker_app(_settings())
        subscribers = app.brokers[0].subscribers
        assert len(subscribers) == 2
        assert {s.stream_sub.group for s in subscribers} == {"stats"}

    def test_health_route_registered(self):
        app = create_worker_app(_settings())
        assert "/health" in dict(app.routes)

    def test_claimer_tunables_come_from_settings(self):
        settings = _settings(claim_idle_ms=120_000, batch_size=7, block_ms=500)
        app = create_worker_app(settings)
        specs = [s.stream_sub for s in app.brokers[0].subscribers]
        claimer = next(s for s in specs if s.min_idle_time is not None)
        reader = next(s for s in specs if s.min_idle_time is None)
        assert claimer.min_idle_time == 120_000
        assert reader.max_records == 7
        assert reader.polling_interval == 500


class TestFirstMessageId:
    def test_decodes_bytes_id(self):
        msg = MagicMock()
        msg.raw_message = {"message_ids": [b"17-0"]}
        assert _first_message_id(msg) == "17-0"

    def test_passes_through_str_id(self):
        msg = MagicMock()
        msg.raw_message = {"message_ids": ["17-0"]}
        assert _first_message_id(msg) == "17-0"

    def test_none_when_missing(self):
        msg = MagicMock()
        msg.raw_message = {}
        assert _first_message_id(msg) is None


class TestRuntimeWiring:
    async def test_startup_builds_consumers_for_enabled_groups(self):
        """The startup hook builds one consumer per enabled group and the
        handler closures resolve them through the runtime holder."""
        settings = _settings(hotness_enabled=True)

        fake_runtime = MagicMock()
        fake_runtime.consumers = {"stats": AsyncMock(), "hotness": AsyncMock()}
        fake_runtime.aclose = AsyncMock()

        with patch(
            "workers.click_worker._build_runtime",
            AsyncMock(return_value=fake_runtime),
        ) as build:
            app = create_worker_app(settings)
            # invoke the registered startup/shutdown hooks directly
            await app._on_startup_calling[0]()  # type: ignore[attr-defined]
            build.assert_awaited_once()
            await app._on_shutdown_calling[0]()  # type: ignore[attr-defined]
            fake_runtime.aclose.assert_awaited_once()
