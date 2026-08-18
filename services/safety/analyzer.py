"""SafetyAnalyzer — provider chain → verdict store → enforcement/notify.

The single orchestration point every trigger funnels through, in whichever
process hosts it (worker consumer or inline sink). Semantics:

- A verdict fresher than ``reverdict_ttl`` short-circuits analysis; an
  existing TOXIC verdict re-runs enforcement idempotently instead (new
  links to an already-judged destination die without re-analysis).
- First non-abstaining provider wins. No provider judging means tier
  UNCERTAIN and a human review embed — BENIGN is never inferred from
  absence of evidence.
- Everything is best-effort: analysis failures log and drop, they never
  propagate into the trigger path (a report must store even when analysis
  is broken).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

from infrastructure.logging import get_logger
from infrastructure.ops_notify import OpsNotifier
from repositories.verdict_repository import VerdictRepository
from schemas.enums.safety import VerdictTier
from services.safety.admission import AdmissionPolicy
from services.safety.enforcer import SafetyEnforcer
from services.safety.events import SafetyAnalyzeEvent
from services.safety.providers import AnalysisProvider
from shared.datetime_utils import as_aware_utc

if TYPE_CHECKING:
    # sinks.py imports the analyzer (inline rung), so the sink protocol is
    # only imported for typing to avoid the cycle.
    from services.safety.sinks import DeepAnalysisSink

log = get_logger(__name__)


class SafetyAnalyzer:
    def __init__(
        self,
        providers: list[AnalysisProvider],
        verdict_repo: VerdictRepository,
        enforcer: SafetyEnforcer,
        notifier: OpsNotifier,
        *,
        reverdict_ttl_hours: int = 24,
        admission: AdmissionPolicy | None = None,
        deep_sink: DeepAnalysisSink | None = None,
    ) -> None:
        self._providers = providers
        self._verdict_repo = verdict_repo
        self._enforcer = enforcer
        self._notifier = notifier
        self._reverdict_ttl = timedelta(hours=reverdict_ttl_hours)
        self._admission = admission
        self._deep_sink = deep_sink

    async def analyze(self, event: SafetyAnalyzeEvent) -> None:
        existing = await self._verdict_repo.find_by_host(event.host)
        if existing is not None:
            if existing.tier == VerdictTier.TOXIC:
                # Already judged bad: enforcement is idempotent and cheap,
                # and covers links created after the original block.
                await self._enforcer.block_host(
                    event.host, reason=existing.reason or "previous toxic verdict"
                )
                return
            if existing.decided_by != "system":
                # A human's non-toxic call never goes stale — this is the
                # allowlist: mark a popular domain benign once and its
                # recurring bursts stay silent until a human says otherwise.
                log.info(
                    "safety_analysis_skipped",
                    host=event.host,
                    reason="human_verdict",
                    tier=existing.tier.value,
                )
                return
            updated = as_aware_utc(existing.updated_at)
            if (
                updated is not None
                and datetime.now(timezone.utc) - updated < self._reverdict_ttl
            ):
                log.info(
                    "safety_analysis_skipped",
                    host=event.host,
                    reason="fresh_verdict",
                    tier=existing.tier.value,
                )
                return

        verdict = None
        source = "local_feeds"
        for provider in self._providers:
            verdict = await provider.analyze(
                event.url, event.host, event.registrable_domain
            )
            if verdict is not None:
                source = provider.name
                break

        if verdict is not None and verdict.tier == VerdictTier.TOXIC:
            await self._verdict_repo.upsert_verdict(
                event.host,
                registrable_domain=event.registrable_domain,
                tier=VerdictTier.TOXIC,
                reason=verdict.reason,
                source=source,
                trigger=event.trigger,
                sample_url=event.url,
                context=event.context,
            )
            result = await self._enforcer.block_host(event.host, reason=verdict.reason)
            await self._notifier.safety_action(
                host=event.host,
                reason=verdict.reason,
                trigger=event.trigger,
                blocked_count=result.blocked_count,
                legacy_count=result.legacy_count,
                sample_url=event.url,
            )
            return

        # No judging source (or a non-toxic provider verdict, none of which
        # exist in v1): record UNCERTAIN and hand it to a human with the
        # trigger context attached.
        await self._verdict_repo.upsert_verdict(
            event.host,
            registrable_domain=event.registrable_domain,
            tier=VerdictTier.UNCERTAIN,
            reason=verdict.reason if verdict else None,
            source=source if verdict else "none",
            trigger=event.trigger,
            sample_url=event.url,
            context=event.context,
        )
        # Screening ended unresolved — the admission policy decides who
        # crosses into investigation (the deep tier's own queue). Admitted
        # events skip the immediate review embed: the investigation will
        # come back with a richer result, and two pings for one host is
        # exactly the spam the two-stage split exists to prevent.
        if self._admission is not None and self._deep_sink is not None:
            decision = await self._admission.decide(event)
            if decision.admitted:
                await self._deep_sink.emit(event)
                log.info(
                    "safety_deep_admitted",
                    host=event.host,
                    trigger=event.trigger,
                    reason=decision.reason,
                )
                return
            log.info(
                "safety_deep_denied",
                host=event.host,
                trigger=event.trigger,
                reason=decision.reason,
            )
        if event.trigger == "sweep":
            # Coverage screening: the uncertain verdict IS the record.
            # Pinging review for every innocent new destination would make
            # the sweeper a spam machine; only reports and anomalies ask
            # for human eyes.
            log.info("safety_screened", host=event.host)
            return
        await self._notifier.safety_review(
            host=event.host,
            trigger=event.trigger,
            sample_url=event.url,
            context=event.context,
        )
