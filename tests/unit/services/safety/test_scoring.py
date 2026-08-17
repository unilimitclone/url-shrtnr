"""Unit tests for CreationPatternScorer (L1)."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from services.safety.scoring import CreationPatternScorer, _hash_ip


def _redis(counts: list[int]) -> MagicMock:
    """Fake redis whose pipeline returns interleaved incr/expire results
    for however many keys the scorer bumped."""
    redis = MagicMock()
    pipe = MagicMock()
    results: list = []
    for c in counts:
        results.extend([c, True])
    pipe.execute = AsyncMock(return_value=results)
    redis.pipeline = MagicMock(return_value=pipe)
    return redis, pipe


def _scorer(redis, *, sink=None, notifier=None, **thresholds):
    defaults = dict(
        burst_window_seconds=600,
        domain_burst_threshold=3,
        domain_daily_threshold=10,
        ip_burst_threshold=4,
        ip_daily_threshold=20,
    )
    defaults.update(thresholds)
    return CreationPatternScorer(
        redis, sink or AsyncMock(), notifier or AsyncMock(), **defaults
    )


class TestCounters:
    @pytest.mark.asyncio
    async def test_bumps_four_counters_with_ip(self):
        redis, pipe = _redis([1, 1, 1, 1])
        scorer = _scorer(redis)

        await scorer.record_create(
            "https://a.evil.com/x", "a.evil.com", "evil.com", "1.2.3.4"
        )

        keys = [call.args[0] for call in pipe.incr.call_args_list]
        assert len(keys) == 4
        assert keys[0].startswith("l1:dom:600:evil.com:")
        assert keys[1].startswith("l1:dom:86400:evil.com:")
        ip_hash = _hash_ip("1.2.3.4")
        assert keys[2].startswith(f"l1:ip:600:{ip_hash}:")
        assert keys[3].startswith(f"l1:ip:86400:{ip_hash}:")
        # Raw IP never appears in any key.
        assert not any("1.2.3.4" in k for k in keys)

    @pytest.mark.asyncio
    async def test_no_ip_bumps_domain_counters_only(self):
        redis, pipe = _redis([1, 1])
        await _scorer(redis).record_create(
            "https://a.evil.com/x", "a.evil.com", "evil.com", None
        )
        assert len(pipe.incr.call_args_list) == 2

    @pytest.mark.asyncio
    async def test_no_redis_is_a_noop(self):
        sink = AsyncMock()
        scorer = _scorer(None, sink=sink)
        await scorer.record_create("https://a.com/x", "a.com", "a.com", "1.2.3.4")
        sink.emit.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_redis_failure_never_raises(self):
        redis = MagicMock()
        redis.pipeline = MagicMock(side_effect=RuntimeError("redis down"))
        await _scorer(redis).record_create(
            "https://a.com/x", "a.com", "a.com", "1.2.3.4"
        )


class TestThresholds:
    @pytest.mark.asyncio
    async def test_domain_burst_crossing_enqueues_analysis(self):
        sink = AsyncMock()
        redis, _ = _redis([3, 5, 1, 1])  # burst hits threshold exactly
        await _scorer(redis, sink=sink).record_create(
            "https://a.evil.com/x", "a.evil.com", "evil.com", "1.2.3.4"
        )
        event = sink.emit.await_args.args[0]
        assert event.trigger == "pattern"
        assert event.host == "a.evil.com"
        assert event.registrable_domain == "evil.com"
        assert event.context == {"window_seconds": 600, "creates": 3}

    @pytest.mark.asyncio
    async def test_fires_once_per_window(self):
        """Exact equality: over the threshold means the window already
        fired — no event storm from a sustained campaign."""
        sink = AsyncMock()
        redis, _ = _redis([4, 5, 1, 1])  # burst already past threshold
        await _scorer(redis, sink=sink).record_create(
            "https://a.evil.com/x", "a.evil.com", "evil.com", "1.2.3.4"
        )
        sink.emit.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_daily_domain_crossing_enqueues_analysis(self):
        sink = AsyncMock()
        redis, _ = _redis([1, 10, 1, 1])
        await _scorer(redis, sink=sink).record_create(
            "https://a.evil.com/x", "a.evil.com", "evil.com", "1.2.3.4"
        )
        assert sink.emit.await_args.args[0].context["window_seconds"] == 86_400

    @pytest.mark.asyncio
    async def test_ip_burst_notifies_review_not_analysis(self):
        sink = AsyncMock()
        notifier = AsyncMock()
        redis, _ = _redis([1, 1, 4, 5])
        await _scorer(redis, sink=sink, notifier=notifier).record_create(
            "https://a.evil.com/x", "a.evil.com", "evil.com", "1.2.3.4"
        )
        sink.emit.assert_not_awaited()
        kwargs = notifier.safety_review.await_args.kwargs
        assert kwargs["trigger"] == "pattern"
        assert kwargs["context"]["ip_hash"] == _hash_ip("1.2.3.4")
        assert kwargs["context"]["creates"] == 4
