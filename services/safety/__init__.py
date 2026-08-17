"""URL safety pipeline — the report vertical slice.

Flow: a trigger (reports today; hot links, creation patterns and sweeps
later) emits a ``safety.analyze`` event → the analyzer runs a provider
chain over the destination → the verdict lands in ``safety_verdicts`` →
toxic verdicts are enforced immediately (status flip + cache and edge
eviction + link.blocked events) and everything unjudged goes to a human
review embed. Detection computes once per destination host; the redirect
path only ever reads stored state.
"""

from services.safety.analyzer import SafetyAnalyzer
from services.safety.enforcer import EnforcementResult, SafetyEnforcer
from services.safety.events import SAFETY_STREAM, SafetyAnalyzeEvent
from services.safety.feeds import (
    FISHFISH_FEED,
    MANUAL_FEED,
    SHORTENER_FEED,
    FishFishClient,
    build_feed_providers,
    build_feed_tasks,
    ensure_feed_seeds,
    fishfish_sync_task,
    load_shortener_seed,
)
from services.safety.policy import PolicyRejection, UrlPolicyService
from services.safety.providers import (
    AnalysisProvider,
    BlockedPatternProvider,
    FeedDomainProvider,
    ProviderVerdict,
    ToxicVerdictProvider,
    WebRiskProvider,
)
from services.safety.scoring import CreationPatternScorer
from services.safety.sinks import (
    InlineSafetySink,
    NullSafetySink,
    RedisStreamSafetySink,
    SafetySink,
)

__all__ = [
    "FISHFISH_FEED",
    "MANUAL_FEED",
    "SAFETY_STREAM",
    "SHORTENER_FEED",
    "AnalysisProvider",
    "BlockedPatternProvider",
    "CreationPatternScorer",
    "EnforcementResult",
    "FeedDomainProvider",
    "FishFishClient",
    "InlineSafetySink",
    "NullSafetySink",
    "PolicyRejection",
    "ProviderVerdict",
    "RedisStreamSafetySink",
    "SafetyAnalyzeEvent",
    "SafetyAnalyzer",
    "SafetyEnforcer",
    "SafetySink",
    "ToxicVerdictProvider",
    "UrlPolicyService",
    "WebRiskProvider",
    "build_feed_providers",
    "build_feed_tasks",
    "ensure_feed_seeds",
    "fishfish_sync_task",
    "load_shortener_seed",
]
