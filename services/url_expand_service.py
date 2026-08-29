"""Redirect-chain expansion behind GET /api/v1/expand (the URL expander
tool). Follows the chain with the shared SSRF-guarded fetcher and
annotates it with the one safety signal we can honestly compute today:
whether any hop matches the abuse blocklist enforced at link creation."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone

from infrastructure.cache.meta_fetch_cache import MetaFetchCache
from infrastructure.logging import get_logger
from infrastructure.safe_fetch import expand_public
from infrastructure.web_risk import WebRiskClient
from repositories.blocked_url_repository import BlockedUrlRepository
from shared.validators import validate_blocked_url

log = get_logger(__name__)


class UrlExpandService:
    def __init__(
        self,
        blocked_url_repo: BlockedUrlRepository,
        cache: MetaFetchCache,
        *,
        regex_timeout: float,
        user_agent: str,
        web_risk: WebRiskClient | None = None,
    ) -> None:
        self._blocked_url_repo = blocked_url_repo
        self._cache = cache
        self._regex_timeout = regex_timeout
        self._user_agent = user_agent
        self._web_risk = web_risk

    async def expand(self, url: str) -> dict:
        cached = await self._cache.get(url)
        if cached is not None:
            return cached

        chain = await expand_public(url, user_agent=self._user_agent)

        patterns = await self._blocked_url_repo.get_patterns()
        urls = [hop.url for hop in chain.hops] + [chain.final_url]
        blocklist_match, web_risk = await asyncio.gather(
            asyncio.to_thread(self._any_blocked, urls, patterns),
            self._web_risk_verdict(chain.final_url),
        )

        payload = {
            "url": url,
            "final_url": chain.final_url,
            "final_status": chain.final_status,
            "truncated": chain.truncated,
            "hops": [
                {
                    "url": hop.url,
                    "status": hop.status,
                    "https": hop.url.startswith("https://"),
                }
                for hop in chain.hops
            ],
            "blocklist_match": blocklist_match,
            "web_risk": web_risk,
            "fetched_at": datetime.now(timezone.utc).isoformat(),
        }
        # A configured-but-failing Web Risk call returns None, and caching
        # that would hide the safety signal for the whole TTL. Skip the
        # write so the next caller asks again.
        if not (self._web_risk and web_risk is None):
            await self._cache.set(url, payload)
        return payload

    async def _web_risk_verdict(self, url: str) -> dict | None:
        """Google Web Risk verdict for the final URL. None whenever the
        check didn't run (no key, API error) — absence, never a verdict."""
        if self._web_risk is None:
            return None
        threats = await self._web_risk.lookup(url)
        if threats is None:
            return None
        return {"checked": True, "threats": threats}

    def _any_blocked(self, urls: list[str], patterns: list[str]) -> bool:
        seen: set[str] = set()
        for url in urls:
            if url in seen:
                continue
            seen.add(url)
            if not validate_blocked_url(url, patterns, timeout=self._regex_timeout):
                return True
        return False
