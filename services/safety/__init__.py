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
    FishFishClient,
    fishfish_sync_task,
)
from services.safety.policy import PolicyRejection, UrlPolicyService
from services.safety.providers import (
    AnalysisProvider,
    BlockedPatternProvider,
    FeedDomainProvider,
    ProviderVerdict,
    WebRiskProvider,
)
from services.safety.sinks import (
    InlineSafetySink,
    NullSafetySink,
    RedisStreamSafetySink,
    SafetySink,
)

__all__ = [
    "FISHFISH_FEED",
    "SAFETY_STREAM",
    "AnalysisProvider",
    "BlockedPatternProvider",
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
    "UrlPolicyService",
    "WebRiskProvider",
    "fishfish_sync_task",
]
