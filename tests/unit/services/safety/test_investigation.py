"""Unit tests for L2 investigation — the authority mapper (safety-critical
pure function) and the investigator flow."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from infrastructure.llm import LlmTaskFailed
from schemas.enums.safety import VerdictTier
from services.safety.events import SafetyAnalyzeEvent
from services.safety.investigation import (
    AutoBlockPolicy,
    Classification,
    Confidence,
    DeepInvestigator,
    InvestigationVerdict,
    Scope,
    decide_authority,
)


def _verdict(cls, conf=Confidence.HIGH, scope=Scope.HOST, **kw) -> InvestigationVerdict:
    return InvestigationVerdict(
        classification=cls,
        confidence=conf,
        reason="because",
        scope=scope,
        **kw,
    )


class TestAuthorityMapper:
    """Blast radius is the axis: self-limiting verdicts apply themselves;
    anything reaching future links waits for a human."""

    def test_corroborated_high_scam_blocks_host(self):
        d = decide_authority(
            _verdict(Classification.SCAM_HOST),
            corroborated=True,
            policy=AutoBlockPolicy.CORROBORATED,
        )
        assert d.action == "block_host" and d.auto and d.tier == VerdictTier.TOXIC

    def test_uncorroborated_scam_goes_to_review_under_default(self):
        d = decide_authority(
            _verdict(Classification.SCAM_HOST),
            corroborated=False,
            policy=AutoBlockPolicy.CORROBORATED,
        )
        assert d.action == "review" and not d.auto

    def test_compromised_legit_never_blocks_the_host(self):
        d = decide_authority(
            _verdict(Classification.COMPROMISED_LEGIT, scope=Scope.LINKS),
            corroborated=True,
            policy=AutoBlockPolicy.CORROBORATED,
        )
        assert d.action == "block_aliases" and d.auto

    def test_redirector_service_always_needs_a_human_tap(self):
        # Even fully corroborated and high-confidence: a list add reaches
        # every future link to the service.
        d = decide_authority(
            _verdict(Classification.REDIRECTOR_SERVICE),
            corroborated=True,
            policy=AutoBlockPolicy.CONFIDENT,
        )
        assert d.action == "propose" and not d.auto and d.tier == VerdictTier.GRAY

    def test_legit_relay_is_a_benign_verdict(self):
        d = decide_authority(
            _verdict(Classification.LEGIT_RELAY),
            corroborated=False,
            policy=AutoBlockPolicy.CORROBORATED,
        )
        assert d.action == "benign" and d.tier == VerdictTier.BENIGN

    def test_spam_gray_records_but_never_blocks(self):
        d = decide_authority(
            _verdict(Classification.SPAM_GRAY),
            corroborated=True,
            policy=AutoBlockPolicy.CONFIDENT,
        )
        assert d.action == "benign" and d.tier == VerdictTier.GRAY

    def test_uncertain_always_reviews(self):
        d = decide_authority(
            _verdict(Classification.UNCERTAIN, conf=Confidence.LOW),
            corroborated=True,
            policy=AutoBlockPolicy.CONFIDENT,
        )
        assert d.action == "review" and d.tier == VerdictTier.UNCERTAIN

    def test_confident_policy_blocks_model_alone(self):
        d = decide_authority(
            _verdict(Classification.SCAM_HOST),
            corroborated=False,
            policy=AutoBlockPolicy.CONFIDENT,
        )
        assert d.action == "block_host" and d.auto

    def test_confident_policy_still_needs_high_confidence(self):
        d = decide_authority(
            _verdict(Classification.SCAM_HOST, conf=Confidence.MEDIUM),
            corroborated=False,
            policy=AutoBlockPolicy.CONFIDENT,
        )
        assert d.action == "review"

    def test_both_policy_requires_confidence_and_corroboration(self):
        confident_only = decide_authority(
            _verdict(Classification.SCAM_HOST),
            corroborated=False,
            policy=AutoBlockPolicy.BOTH,
        )
        assert confident_only.action == "review"
        full = decide_authority(
            _verdict(Classification.SCAM_HOST),
            corroborated=True,
            policy=AutoBlockPolicy.BOTH,
        )
        assert full.action == "block_host"

    def test_off_policy_never_auto_blocks(self):
        d = decide_authority(
            _verdict(Classification.SCAM_HOST),
            corroborated=True,
            policy=AutoBlockPolicy.OFF,
        )
        assert d.action == "review" and not d.auto


def _event(trigger="report", **ctx) -> SafetyAnalyzeEvent:
    return SafetyAnalyzeEvent(
        url="https://evil.example/login",
        host="evil.example",
        registrable_domain="evil.example",
        trigger=trigger,
        context={"reasons": ["phishing"], "reported_codes": ["spoo.me/abc"], **ctx},
    )


def _investigator(verdict_or_exc, *, policy=AutoBlockPolicy.CORROBORATED):
    runner = AsyncMock()
    if isinstance(verdict_or_exc, Exception):
        runner.run = AsyncMock(side_effect=verdict_or_exc)
    else:
        runner.run = AsyncMock(return_value=verdict_or_exc)
    url_repo = AsyncMock()
    url_repo.destination_history = AsyncMock(
        return_value={
            "link_count": 3,
            "anon_count": 3,
            "owned_count": 0,
            "distinct_owners": 0,
            "total_clicks": 40,
            "first_seen": "2026-08-01T00:00:00+00:00",
            "edited_count": 0,
        }
    )
    verdict_repo = AsyncMock()
    enforcer = AsyncMock()
    enforcer.block_host = AsyncMock(
        return_value=AsyncMock(blocked_count=3, legacy_count=1)
    )
    enforcer.block_aliases = AsyncMock(return_value=AsyncMock(blocked_count=1))
    notifier = AsyncMock()
    inv = DeepInvestigator(
        runner,
        AsyncMock(versioned_prompt="v1+abcd1234"),
        url_repo,
        verdict_repo,
        enforcer,
        notifier,
        policy=policy,
        model_name="anthropic:claude-sonnet-5",
    )
    return inv, verdict_repo, enforcer, notifier


class TestInvestigatorFlow:
    @pytest.mark.asyncio
    async def test_reported_scam_blocks_and_records_provenance(self):
        inv, verdict_repo, enforcer, notifier = _investigator(
            _verdict(Classification.SCAM_HOST, evidence=["cross-origin password form"])
        )
        await inv.investigate(_event())
        enforcer.block_host.assert_awaited_once()
        notifier.safety_action.assert_awaited_once()
        kwargs = verdict_repo.upsert_verdict.await_args.kwargs
        assert kwargs["tier"] == VerdictTier.TOXIC
        assert kwargs["source"] == "llm"
        prov = kwargs["provenance"]
        assert prov["classification"] == "scam_host"
        assert prov["corroborated"] is True
        assert prov["prompt_version"] == "v1+abcd1234"

    @pytest.mark.asyncio
    async def test_burst_scam_without_hard_source_reviews_not_blocks(self):
        inv, _, enforcer, notifier = _investigator(
            _verdict(Classification.SCAM_HOST, evidence=["looks phishy"]),
        )
        await inv.investigate(_event(trigger="pattern"))
        enforcer.block_host.assert_not_awaited()
        notifier.safety_review.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_burst_scam_self_corroborated_by_feed_hit_blocks(self):
        """A feed hit the model found via feed_lookup is an independent
        hard source even without a report."""
        inv, _, enforcer, _ = _investigator(
            _verdict(
                Classification.SCAM_HOST,
                evidence=["HARD HITS on evil.example: feed:fishfish"],
            ),
        )
        await inv.investigate(_event(trigger="pattern"))
        enforcer.block_host.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_compromised_legit_blocks_only_reported_aliases(self):
        inv, _, enforcer, _ = _investigator(
            _verdict(Classification.COMPROMISED_LEGIT, scope=Scope.LINKS)
        )
        await inv.investigate(_event(reported_codes=["spoo.me/abc", "custom.com/xyz"]))
        enforcer.block_host.assert_not_awaited()
        pairs = enforcer.block_aliases.await_args.args[0]
        assert ("abc", "spoo.me") in pairs and ("xyz", "custom.com") in pairs

    @pytest.mark.asyncio
    async def test_model_failure_degrades_to_uncertain_and_review(self):
        inv, verdict_repo, enforcer, notifier = _investigator(
            LlmTaskFailed("safety-investigate", "timeout")
        )
        await inv.investigate(_event())
        enforcer.block_host.assert_not_awaited()
        assert verdict_repo.upsert_verdict.await_args.kwargs["tier"] == (
            VerdictTier.UNCERTAIN
        )
        notifier.safety_review.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_failed_sweep_investigation_stays_silent(self):
        inv, _, _, notifier = _investigator(
            LlmTaskFailed("safety-investigate", "model_error")
        )
        await inv.investigate(_event(trigger="sweep"))
        notifier.safety_review.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_redirector_proposal_goes_to_review(self):
        from services.safety.investigation import ListProposal

        inv, _, enforcer, notifier = _investigator(
            _verdict(
                Classification.REDIRECTOR_SERVICE,
                proposals=[
                    ListProposal(list="shorteners", domain="sus.link", why="cloak")
                ],
            )
        )
        await inv.investigate(_event())
        enforcer.block_host.assert_not_awaited()
        review_ctx = notifier.safety_review.await_args.kwargs["context"]
        assert review_ctx["needs"] == "list proposal"
        assert review_ctx["proposals"][0]["domain"] == "sus.link"
