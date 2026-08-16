"""Analysis providers — the pluggable judgment sources.

Each provider inspects one signal and either returns a verdict or
abstains (None). Providers must never raise on bad input or backend
failure: safety analysis is best-effort by contract and a broken provider
degrades to abstention, not to a stuck queue. The chain is ordered; the
first non-abstaining provider wins.

v1 ships the local sources (operator blocklists). The deep tier (page
render + LLM) plugs in here as another provider without touching the
pipeline.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from infrastructure.logging import get_logger
from repositories.blocked_domain_repository import BlockedDomainRepository
from repositories.blocked_url_repository import BlockedUrlRepository
from schemas.enums.safety import VerdictTier
from shared.validators import validate_blocked_url

log = get_logger(__name__)


@dataclass(frozen=True)
class ProviderVerdict:
    tier: VerdictTier
    reason: str


class AnalysisProvider(Protocol):
    name: str

    async def analyze(
        self, url: str, host: str, registrable_domain: str
    ) -> ProviderVerdict | None: ...


class BlockedDomainProvider:
    """Exact-domain blocklist (the ``blocked_domains`` collection): a hit
    on the host or its registrable domain is an operator-confirmed bad
    destination."""

    name = "blocked_domain"

    def __init__(self, repo: BlockedDomainRepository) -> None:
        self._repo = repo

    async def analyze(
        self, url: str, host: str, registrable_domain: str
    ) -> ProviderVerdict | None:
        try:
            if await self._repo.is_blocked(host):
                return ProviderVerdict(
                    tier=VerdictTier.TOXIC,
                    reason=f"host {host} is on the domain blocklist",
                )
            if (
                registrable_domain
                and registrable_domain != host
                and await self._repo.is_blocked(registrable_domain)
            ):
                return ProviderVerdict(
                    tier=VerdictTier.TOXIC,
                    reason=f"domain {registrable_domain} is on the domain blocklist",
                )
        except Exception as exc:
            log.warning("safety_provider_failed", provider=self.name, error=str(exc))
        return None


class BlockedPatternProvider:
    """Regex blocklist (the ``blocked-urls`` collection) evaluated against
    the full destination URL — the same patterns the create gate uses, so
    a reported link that predates a pattern still gets caught."""

    name = "blocked_pattern"

    def __init__(self, repo: BlockedUrlRepository, *, regex_timeout: float) -> None:
        self._repo = repo
        self._timeout = regex_timeout

    async def analyze(
        self, url: str, host: str, registrable_domain: str
    ) -> ProviderVerdict | None:
        try:
            patterns = await self._repo.get_patterns()
            # validate_blocked_url returns True = ALLOWED (inverted name).
            if not validate_blocked_url(url, patterns, timeout=self._timeout):
                return ProviderVerdict(
                    tier=VerdictTier.TOXIC,
                    reason="destination matches an operator blocklist pattern",
                )
        except Exception as exc:
            log.warning("safety_provider_failed", provider=self.name, error=str(exc))
        return None
