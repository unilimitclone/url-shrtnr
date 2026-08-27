"""SafetyAnalyzer — provider chain → verdict store → enforcement/notify.

The single orchestration point every trigger funnels through, in whichever
process hosts it (worker consumer or inline sink). Semantics:

- A verdict fresher than ``reverdict_ttl`` short-circuits analysis; an
  existing TOXIC verdict re-runs enforcement idempotently instead (new
  links to an already-judged destination die without re-analysis) —
  bounded by the verdict's SCOPE, so a pattern-scoped judgment on a
  shared platform never widens into a host block.
- First non-abstaining provider wins. No provider judging means tier
  UNCERTAIN and a human review embed — BENIGN is never inferred from
  absence of evidence.
- Screening never ORIGINATES a host-wide block. A fresh toxic signal
  blocks only the links its evidence actually covers (the matched
  pattern, or the judged URL), then escalates the host-wide question to
  the investigation tier — a host block is the most destructive action
  in the system and requires the deep tier's evidence or a human.
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
from schemas.models.verdict import VerdictDoc
from services.safety.admission import AdmissionPolicy
from services.safety.enforcer import SafetyEnforcer
from services.safety.events import SafetyAnalyzeEvent
from services.safety.providers import AnalysisProvider, ProviderVerdict
from shared.datetime_utils import as_aware_utc
from shared.validators import matching_blocked_pattern

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
            if existing.tier == VerdictTier.TOXIC and await self._reenforce(
                event, existing
            ):
                return
            # A narrow toxic verdict that does not cover this URL falls
            # through: the event is evidence about a DIFFERENT path on the
            # same host and gets the same gates as any other known host.
            if existing.decided_by != "system":
                # A human's call never goes stale — this is the allowlist:
                # mark a popular domain benign (or its bad path toxic) once
                # and recurring events stay silent until a human says
                # otherwise.
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
            await self._handle_toxic(event, verdict, source)
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
        if await self._admit_deep(event):
            return
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

    async def _handle_toxic(
        self, event: SafetyAnalyzeEvent, verdict: ProviderVerdict, source: str
    ) -> None:
        """Enforce exactly as far as the signal reaches, never wider. The
        stored scope is what the create gate and later re-enforcement will
        honor; the host-wide question goes to the deep tier, whose
        authority mapper may widen the verdict with real evidence."""
        if verdict.scope == "path_pattern" and verdict.path_pattern:
            scope, path_pattern = "path_pattern", verdict.path_pattern

            def matcher(u: str, _p: str = verdict.path_pattern) -> bool:
                return matching_blocked_pattern(u, (_p,)) is not None

            scope_note = f"scoped to pattern {path_pattern}"
        else:
            # URL-scoped and host-scoped signals both enforce on the judged
            # URL only: a host-wide claim (a feed listing) is exactly what
            # the deep tier exists to confirm before anyone acts on it.
            scope, path_pattern = "links", None

            def matcher(u: str, _u: str = event.url) -> bool:
                return u == _u

            scope_note = "scoped to the judged URL"

        await self._verdict_repo.upsert_verdict(
            event.host,
            registrable_domain=event.registrable_domain,
            tier=VerdictTier.TOXIC,
            reason=verdict.reason,
            source=source,
            trigger=event.trigger,
            sample_url=event.url,
            context=event.context,
            scope=scope,
            path_pattern=path_pattern,
        )
        result = await self._enforcer.block_matching(
            event.host, matcher=matcher, reason=verdict.reason
        )
        escalated = await self._escalate(event, verdict, source)
        follow_up = (
            "host-wide decision sent to investigation"
            if escalated
            else "host-wide decision needs review"
        )
        await self._notifier.safety_action(
            host=event.host,
            reason=f"{verdict.reason} ({scope_note}; {follow_up})",
            trigger=event.trigger,
            blocked_count=result.blocked_count,
            legacy_count=result.legacy_count,
            sample_url=event.url,
        )

    async def _reenforce(self, event: SafetyAnalyzeEvent, existing: VerdictDoc) -> bool:
        """Idempotent re-enforcement of a stored toxic verdict, bounded by
        its scope. Returns True when the verdict covers this event's URL
        (nothing left to analyze); a narrow verdict that does not cover it
        returns False so the event gets a fresh look."""
        reason = existing.reason or "previous toxic verdict"
        scope = existing.scope or "host"
        if scope == "host":
            # Already judged bad host-wide (deep tier or human): cheap,
            # idempotent, and covers links created after the original block.
            await self._enforcer.block_host(event.host, reason=reason)
            return True
        if scope == "path_pattern" and existing.path_pattern:
            pattern = existing.path_pattern
            await self._enforcer.block_matching(
                event.host,
                matcher=lambda u: matching_blocked_pattern(u, (pattern,)) is not None,
                reason=reason,
            )
            return matching_blocked_pattern(event.url, (pattern,)) is not None
        # links scope: the judged links are already blocked and the create
        # gate refuses the exact URL; nothing host-side to re-run.
        return event.url == existing.sample_url

    async def _escalate(
        self, event: SafetyAnalyzeEvent, verdict: ProviderVerdict, source: str
    ) -> bool:
        """Hand the host-wide question to the investigation tier, carrying
        the screening finding as context (it is the corroborating hard
        signal the deep tier's authority mapper gates auto-block on)."""
        if self._admission is None or self._deep_sink is None:
            return False
        decision = await self._admission.decide(event, escalation=True)
        if not decision.admitted:
            log.info(
                "safety_deep_denied",
                host=event.host,
                trigger=event.trigger,
                reason=decision.reason,
            )
            return False
        await self._deep_sink.emit(
            SafetyAnalyzeEvent(
                url=event.url,
                host=event.host,
                registrable_domain=event.registrable_domain,
                trigger=event.trigger,
                context={
                    **(event.context or {}),
                    "screening": f"{source}: {verdict.reason}",
                },
            )
        )
        log.info(
            "safety_deep_admitted",
            host=event.host,
            trigger=event.trigger,
            reason=decision.reason,
        )
        return True

    async def _admit_deep(self, event: SafetyAnalyzeEvent) -> bool:
        if self._admission is None or self._deep_sink is None:
            return False
        decision = await self._admission.decide(event)
        if decision.admitted:
            await self._deep_sink.emit(event)
            log.info(
                "safety_deep_admitted",
                host=event.host,
                trigger=event.trigger,
                reason=decision.reason,
            )
            return True
        log.info(
            "safety_deep_denied",
            host=event.host,
            trigger=event.trigger,
            reason=decision.reason,
        )
        return False
