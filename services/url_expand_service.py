"""Redirect-chain expansion behind GET /api/v1/expand (the URL expander
tool). Follows the chain with the shared SSRF-guarded fetcher and
annotates it with the one safety signal we can honestly compute today:
whether any hop matches the abuse blocklist enforced at link creation."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone

from infrastructure.cache.meta_fetch_cache import MetaFetchCache
from infrastructure.safe_fetch import expand_public
from repositories.blocked_url_repository import BlockedUrlRepository
from shared.validators import validate_blocked_url


class UrlExpandService:
    def __init__(
        self,
        blocked_url_repo: BlockedUrlRepository,
        cache: MetaFetchCache,
        *,
        regex_timeout: float,
        user_agent: str,
    ) -> None:
        self._blocked_url_repo = blocked_url_repo
        self._cache = cache
        self._regex_timeout = regex_timeout
        self._user_agent = user_agent

    async def expand(self, url: str) -> dict:
        cached = await self._cache.get(url)
        if cached is not None:
            return cached

        chain = await expand_public(url, user_agent=self._user_agent)

        patterns = await self._blocked_url_repo.get_patterns()
        urls = [hop.url for hop in chain.hops] + [chain.final_url]
        blocklist_match = await asyncio.to_thread(self._any_blocked, urls, patterns)

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
            "fetched_at": datetime.now(timezone.utc).isoformat(),
        }
        await self._cache.set(url, payload)
        return payload

    def _any_blocked(self, urls: list[str], patterns: list[str]) -> bool:
        seen: set[str] = set()
        for url in urls:
            if url in seen:
                continue
            seen.add(url)
            if not validate_blocked_url(url, patterns, timeout=self._regex_timeout):
                return True
        return False
