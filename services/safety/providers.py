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

from infrastructure.http_client import HttpClient
from infrastructure.logging import get_logger
from repositories.blocked_domain_repository import BlockedDomainRepository
from repositories.blocked_url_repository import BlockedUrlRepository
from repositories.feed_domain_repository import FeedDomainRepository
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


class FeedDomainProvider:
    """Membership check against a synced external feed's domain set
    (``safety_feed_domains``). An empty or never-synced set abstains — the
    feed layer is additive signal, never a gate on its own health."""

    def __init__(
        self, repo: FeedDomainRepository, *, feed: str, reason_label: str
    ) -> None:
        self._repo = repo
        self._feed = feed
        self._label = reason_label
        self.name = f"feed_{feed}"

    async def analyze(
        self, url: str, host: str, registrable_domain: str
    ) -> ProviderVerdict | None:
        try:
            if await self._repo.contains(self._feed, host):
                return ProviderVerdict(
                    tier=VerdictTier.TOXIC,
                    reason=f"host {host} is listed by {self._label}",
                )
            if (
                registrable_domain
                and registrable_domain != host
                and await self._repo.contains(self._feed, registrable_domain)
            ):
                return ProviderVerdict(
                    tier=VerdictTier.TOXIC,
                    reason=f"domain {registrable_domain} is listed by {self._label}",
                )
        except Exception as exc:
            log.warning("safety_provider_failed", provider=self.name, error=str(exc))
        return None


class WebRiskProvider:
    """Google Web Risk Lookup API (``uris:search``) — judges the full URL
    against Google's MALWARE and SOCIAL_ENGINEERING lists. Online lookup
    (100k/month free tier covers report-triggered volume by orders of
    magnitude); the local hash-DB variant is a later create-gate concern.

    Network or quota failures abstain. The API key never appears in logs.
    """

    name = "web_risk"

    _THREAT_TYPES = ("MALWARE", "SOCIAL_ENGINEERING")

    def __init__(
        self,
        http_client: HttpClient,
        *,
        api_key: str,
        api_base: str = "https://webrisk.googleapis.com",
    ) -> None:
        self._http = http_client
        self._api_key = api_key
        self._api_base = api_base.rstrip("/")

    async def analyze(
        self, url: str, host: str, registrable_domain: str
    ) -> ProviderVerdict | None:
        try:
            response = await self._http.get(
                f"{self._api_base}/v1/uris:search",
                params={
                    "uri": url,
                    "threatTypes": list(self._THREAT_TYPES),
                    "key": self._api_key,
                },
                timeout=10.0,
            )
            if response.status_code != 200:
                log.warning(
                    "safety_provider_failed",
                    provider=self.name,
                    error=f"http {response.status_code}",
                )
                return None
            threat = response.json().get("threat")
            if threat:
                types = ",".join(threat.get("threatTypes", [])) or "UNKNOWN"
                return ProviderVerdict(
                    tier=VerdictTier.TOXIC,
                    reason=f"flagged by Google Web Risk ({types})",
                )
        except Exception as exc:
            log.warning(
                "safety_provider_failed",
                provider=self.name,
                error=type(exc).__name__,
            )
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
