"""UrlPolicyService — the L0 create/edit gate.

One gate, three callers (v2 create, v2 edit, both legacy creation routes).
It reuses the analyzer's providers — the SAME instances, composed by the
wiring into a cheap/local subset — so a signal is implemented once and
fires at two moments: here it refuses the write, in the analyzer it
writes a verdict and enforces.

Output is a ``PolicyRejection``, not a harm verdict: each caller owns its
wire shape (v2 raises ValidationError, the legacy routes return their
frozen JSON bodies). Security rejections stay COARSE on the wire ("URL is
blocked") while the precise provider and reason go to logs — a precise
error message is an evasion oracle.

Failure discipline matches the rest of the funnel: a provider error is an
abstention (the provider logs it), so a broken feed or a Mongo hiccup can
never take down link creation.
"""

from __future__ import annotations

from collections.abc import Sequence

from pydantic import BaseModel, ConfigDict

from infrastructure.logging import get_logger
from schemas.enums.safety import VerdictTier
from services.safety.providers import AnalysisProvider
from shared.url_utils import parse_destination
from shared.validators import validate_url

log = get_logger(__name__)

# Wire-safe messages. Anything security-sourced collapses to the coarse one.
_INVALID_MESSAGE = "URL is not allowed or invalid"
_BLOCKED_MESSAGE = "URL is blocked"


class PolicyRejection(BaseModel):
    """Why the gate said no. ``code`` is the machine reason (logged,
    stored, never necessarily shown); ``public_message`` is safe for any
    wire shape the caller renders."""

    model_config = ConfigDict(frozen=True)

    code: str
    public_message: str


class UrlPolicyService:
    def __init__(
        self,
        providers: Sequence[AnalysisProvider],
        *,
        blocked_self_domains: Sequence[str],
        public_messages: dict[str, str] | None = None,
    ) -> None:
        """``public_messages`` maps provider name -> wire message for
        PUBLISHED policies (e.g. the shortener-chain refusal, which is.gd
        style services document openly). Security-sourced blocks stay on
        the coarse default."""
        self._providers = list(providers)
        self._self_domains = list(blocked_self_domains)
        self._public_messages = public_messages or {}

    async def check(self, url: str) -> PolicyRejection | None:
        """Return the rejection for *url*, or None when it may be written."""
        # Format + scheme allowlist + self-link refusal (pure, existing
        # validator — one code because the validator reports one boolean).
        if not validate_url(url, blocked_self_domains=self._self_domains):
            return PolicyRejection(code="invalid_url", public_message=_INVALID_MESSAGE)

        parts = parse_destination(url)
        host = parts["host"] if parts else ""
        registrable = parts["registrable_domain"] if parts else ""

        for provider in self._providers:
            verdict = await provider.analyze(url, host, registrable)
            if verdict is not None and verdict.tier is VerdictTier.TOXIC:
                # Precise reason to logs, coarse message to the wire.
                log.info(
                    "url_gate_blocked",
                    code=provider.name,
                    reason=verdict.reason,
                )
                return PolicyRejection(
                    code=provider.name,
                    public_message=self._public_messages.get(
                        provider.name, _BLOCKED_MESSAGE
                    ),
                )
        return None
