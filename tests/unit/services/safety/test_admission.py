"""Unit tests for the deep-tier admission policy — the one readable rule
between screening and investigation."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from services.safety.admission import AdmissionPolicy
from services.safety.events import SafetyAnalyzeEvent


def _event(trigger: str) -> SafetyAnalyzeEvent:
    return SafetyAnalyzeEvent(
        url="https://evil.example/kit",
        host="evil.example",
        registrable_domain="evil.example",
        trigger=trigger,
    )


def _redis(used: int = 1) -> AsyncMock:
    r = AsyncMock()
    r.incr = AsyncMock(return_value=used)
    r.expire = AsyncMock()
    return r


class TestAlwaysAdmitted:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("trigger", ["report", "edit"])
    async def test_reports_and_edits_never_consult_the_budget(self, trigger):
        redis = _redis()
        policy = AdmissionPolicy(redis, daily_budget=1)
        decision = await policy.decide(_event(trigger))
        assert decision.admitted and decision.reason == "always"
        redis.incr.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_p0_lane_survives_redis_being_down(self):
        """A report must reach investigation even when the budget counter
        is unreachable — its admission consults nothing."""
        redis = AsyncMock()
        redis.incr = AsyncMock(side_effect=ConnectionError("down"))
        policy = AdmissionPolicy(redis, daily_budget=1)
        assert (await policy.decide(_event("report"))).admitted


class TestBudgetedTriggers:
    @pytest.mark.asyncio
    async def test_pattern_within_budget_admits(self):
        policy = AdmissionPolicy(_redis(used=5), daily_budget=10)
        decision = await policy.decide(_event("pattern"))
        assert decision.admitted and decision.reason == "within_budget"

    @pytest.mark.asyncio
    async def test_pattern_over_budget_denies(self):
        policy = AdmissionPolicy(_redis(used=11), daily_budget=10)
        decision = await policy.decide(_event("pattern"))
        assert not decision.admitted and decision.reason == "budget_exhausted"

    @pytest.mark.asyncio
    async def test_first_use_of_the_day_sets_the_window_ttl(self):
        redis = _redis(used=1)
        await AdmissionPolicy(redis, daily_budget=10).decide(_event("pattern"))
        redis.expire.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_budget_unavailable_fails_closed(self):
        """Investigation is the expensive tier: "we couldn't count, so
        spend freely" is the wrong failure mode."""
        redis = AsyncMock()
        redis.incr = AsyncMock(side_effect=ConnectionError("down"))
        policy = AdmissionPolicy(redis, daily_budget=10)
        decision = await policy.decide(_event("pattern"))
        assert not decision.admitted and decision.reason == "budget_unavailable"


class TestSweeps:
    @pytest.mark.asyncio
    async def test_sweeps_excluded_by_default(self):
        redis = _redis()
        policy = AdmissionPolicy(redis, daily_budget=10)
        decision = await policy.decide(_event("sweep"))
        assert not decision.admitted and decision.reason == "sweep_excluded"
        redis.incr.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_opted_in_sweeps_are_budget_bound(self):
        policy = AdmissionPolicy(_redis(used=11), daily_budget=10, admit_sweeps=True)
        decision = await policy.decide(_event("sweep"))
        assert not decision.admitted and decision.reason == "budget_exhausted"


class TestUnknownTrigger:
    @pytest.mark.asyncio
    async def test_unknown_trigger_is_refused_not_spent_on(self):
        policy = AdmissionPolicy(_redis(), daily_budget=10)
        decision = await policy.decide(_event("mystery"))
        assert not decision.admitted and decision.reason == "unknown_trigger"
