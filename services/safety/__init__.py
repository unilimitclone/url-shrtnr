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
from services.safety.providers import (
    AnalysisProvider,
    BlockedDomainProvider,
    BlockedPatternProvider,
    ProviderVerdict,
)
from services.safety.sinks import (
    InlineSafetySink,
    NullSafetySink,
    RedisStreamSafetySink,
    SafetySink,
)

__all__ = [
    "SAFETY_STREAM",
    "AnalysisProvider",
    "BlockedDomainProvider",
    "BlockedPatternProvider",
    "EnforcementResult",
    "InlineSafetySink",
    "NullSafetySink",
    "ProviderVerdict",
    "RedisStreamSafetySink",
    "SafetyAnalyzeEvent",
    "SafetyAnalyzer",
    "SafetyEnforcer",
    "SafetySink",
]
