"""External threat-feed integrations.

Each feed contributes two pieces: a sync TASK (scheduler-hosted, full-swap
refresh into ``safety_feed_domains``) and membership lookups consumed by
``FeedDomainProvider`` (services/safety/providers.py). Feeds are additive
signal sources — a feed being down, stale, or unconfigured only ever means
abstention, never a broken pipeline.

fishfish.gg: community-run scam-domain feed (strong on the Discord
ecosystem). ``GET /v1/domains`` returns a flat JSON array of domain
strings, no auth required for the domain list.
"""

from __future__ import annotations

from infrastructure.http_client import HttpClient
from infrastructure.logging import get_logger
from repositories.feed_domain_repository import FeedDomainRepository
from services.scheduler.registry import ScheduledTask

log = get_logger(__name__)

FISHFISH_FEED = "fishfish"
FISHFISH_SYNC_TASK = "safety-fishfish-sync"
_FISHFISH_SYNC_CRON = "0 * * * *"
# A feed this small is suspicious (fishfish carries thousands of domains):
# treat it as a bad download rather than a mass delisting, keep the old set.
_FISHFISH_MIN_SANE = 100
_FETCH_TIMEOUT = 30.0


class FishFishClient:
    def __init__(self, http_client: HttpClient, *, api_url: str) -> None:
        self._http = http_client
        self._api_url = api_url

    async def fetch_domains(self) -> list[str]:
        """Download the full domain list. Raises on HTTP/shape errors —
        the sync task records the failure on the task doc."""
        response = await self._http.get(self._api_url, timeout=_FETCH_TIMEOUT)
        response.raise_for_status()
        data = response.json()
        if not isinstance(data, list):
            raise ValueError(f"fishfish returned {type(data).__name__}, expected list")
        return [d for d in data if isinstance(d, str)]


def fishfish_sync_task(
    client: FishFishClient, repo: FeedDomainRepository
) -> ScheduledTask:
    """Hourly full-swap refresh of the fishfish domain set."""

    async def _sync() -> dict | None:
        domains = await client.fetch_domains()
        if len(domains) < _FISHFISH_MIN_SANE:
            log.warning(
                "safety_feed_sync_suspicious",
                feed=FISHFISH_FEED,
                fetched=len(domains),
                detail="below sanity floor, keeping previous set",
            )
            return {"fetched": len(domains), "kept": 0, "skipped": "below_sanity_floor"}
        kept, purged = await repo.replace_feed(FISHFISH_FEED, domains)
        log.info("safety_feed_synced", feed=FISHFISH_FEED, domains=kept, purged=purged)
        return {"domains": kept, "purged": purged}

    return ScheduledTask(
        name=FISHFISH_SYNC_TASK, fn=_sync, schedule=_FISHFISH_SYNC_CRON
    )
