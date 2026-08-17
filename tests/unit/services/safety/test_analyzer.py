"""Unit tests for SafetyAnalyzer orchestration."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock

import pytest

from schemas.enums.safety import VerdictTier
from schemas.models.verdict import VerdictDoc
from services.safety.analyzer import SafetyAnalyzer
from services.safety.events import SafetyAnalyzeEvent
from services.safety.providers import ProviderVerdict


def _event(host="evil.com") -> SafetyAnalyzeEvent:
    return SafetyAnalyzeEvent(
        url=f"https://{host}/kit",
        host=host,
        registrable_domain=host,
        trigger="report",
        context={"report_count": 1},
    )


class _Provider:
    def __init__(self, verdict: ProviderVerdict | None, name="stub"):
        self._verdict = verdict
        self.name = name
        self.calls = 0

    async def analyze(self, url, host, registrable_domain):
        self.calls += 1
        return self._verdict


def _build(providers, existing=None):
    verdict_repo = AsyncMock()
    verdict_repo.find_by_host = AsyncMock(return_value=existing)
    enforcer = AsyncMock()
    enforcer.block_host = AsyncMock(
        return_value=AsyncMock(blocked_count=4, legacy_count=1)
    )
    notifier = AsyncMock()
    analyzer = SafetyAnalyzer(
        providers, verdict_repo, enforcer, notifier, reverdict_ttl_hours=24
    )
    return analyzer, verdict_repo, enforcer, notifier


class TestAnalyze:
    @pytest.mark.asyncio
    async def test_toxic_provider_writes_verdict_enforces_and_notifies(self):
        provider = _Provider(
            ProviderVerdict(tier=VerdictTier.TOXIC, reason="blocklist hit"),
            name="blocked_domain",
        )
        analyzer, verdict_repo, enforcer, notifier = _build([provider])

        await analyzer.analyze(_event())

        kwargs = verdict_repo.upsert_verdict.await_args.kwargs
        assert kwargs["tier"] == VerdictTier.TOXIC
        assert kwargs["source"] == "blocked_domain"
        enforcer.block_host.assert_awaited_once()
        notifier.safety_action.assert_awaited_once()
        notifier.safety_review.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_all_abstain_records_uncertain_and_requests_review(self):
        analyzer, verdict_repo, enforcer, notifier = _build([_Provider(None)])

        await analyzer.analyze(_event())

        kwargs = verdict_repo.upsert_verdict.await_args.kwargs
        assert kwargs["tier"] == VerdictTier.UNCERTAIN
        enforcer.block_host.assert_not_awaited()
        notifier.safety_review.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_existing_toxic_verdict_reenforces_without_reanalysis(self):
        provider = _Provider(None)
        existing = VerdictDoc(
            host="evil.com",
            tier=VerdictTier.TOXIC,
            reason="old verdict",
            updated_at=datetime.now(timezone.utc) - timedelta(days=30),
        )
        analyzer, verdict_repo, enforcer, _notifier = _build([provider], existing)

        await analyzer.analyze(_event())

        assert provider.calls == 0
        enforcer.block_host.assert_awaited_once()
        verdict_repo.upsert_verdict.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_fresh_nontoxic_verdict_short_circuits(self):
        provider = _Provider(None)
        existing = VerdictDoc(
            host="evil.com",
            tier=VerdictTier.UNCERTAIN,
            updated_at=datetime.now(timezone.utc) - timedelta(hours=1),
        )
        analyzer, verdict_repo, _enforcer, notifier = _build([provider], existing)

        await analyzer.analyze(_event())

        assert provider.calls == 0
        verdict_repo.upsert_verdict.assert_not_awaited()
        notifier.safety_review.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_stale_uncertain_verdict_reanalyzes(self):
        provider = _Provider(None)
        existing = VerdictDoc(
            host="evil.com",
            tier=VerdictTier.UNCERTAIN,
            updated_at=datetime.now(timezone.utc) - timedelta(days=3),
        )
        analyzer, verdict_repo, _enforcer, _notifier = _build([provider], existing)

        await analyzer.analyze(_event())

        assert provider.calls == 1
        verdict_repo.upsert_verdict.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_first_provider_wins(self):
        first = _Provider(
            ProviderVerdict(tier=VerdictTier.TOXIC, reason="a"), name="first"
        )
        second = _Provider(
            ProviderVerdict(tier=VerdictTier.TOXIC, reason="b"), name="second"
        )
        analyzer, verdict_repo, _, _ = _build([first, second])

        await analyzer.analyze(_event())

        assert first.calls == 1
        assert second.calls == 0
        assert verdict_repo.upsert_verdict.await_args.kwargs["source"] == "first"


class TestHumanVerdicts:
    @pytest.mark.asyncio
    async def test_human_benign_verdict_never_goes_stale(self):
        """The allowlist: a human marking a popular domain benign silences
        its recurring bursts permanently, however old the verdict is."""
        provider = _Provider(None)
        existing = VerdictDoc(
            host="youtube.com",
            tier=VerdictTier.BENIGN,
            decided_by="human:zingzy",
            updated_at=datetime.now(timezone.utc) - timedelta(days=365),
        )
        analyzer, verdict_repo, enforcer, notifier = _build([provider], existing)

        await analyzer.analyze(_event("youtube.com"))

        assert provider.calls == 0
        verdict_repo.upsert_verdict.assert_not_awaited()
        enforcer.block_host.assert_not_awaited()
        notifier.safety_review.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_human_toxic_verdict_still_enforces(self):
        existing = VerdictDoc(
            host="evil.com",
            tier=VerdictTier.TOXIC,
            decided_by="human:zingzy",
            reason="confirmed phishing",
            updated_at=datetime.now(timezone.utc) - timedelta(days=90),
        )
        analyzer, _verdict_repo, enforcer, _notifier = _build(
            [_Provider(None)], existing
        )

        await analyzer.analyze(_event())

        enforcer.block_host.assert_awaited_once()
