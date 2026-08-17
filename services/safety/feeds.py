"""External threat-feed integrations — FEED_REGISTRY is the catalog as code.

One ``FeedSpec`` entry per feed drives everything (same discipline as the
webhook EVENT_REGISTRY, so nothing can drift): which chains the feed joins
(create gate / analyzer), its config switch, its optional sync task, its
optional first-boot seed, and its L0 wire message. Adding a feed = one
registry entry — the gate, analyzer, wiring, worker and seeder never
change. All feed DATA lives in one place (``safety_feed_domains``), read
through ``FeedDomainProvider`` membership lookups.

Feeds are additive signal sources — a feed being down, stale, or
unconfigured only ever means abstention, never a broken pipeline.

fishfish.gg: community-run scam-domain feed (strong on the Discord
ecosystem). ``GET /v1/domains`` returns a flat JSON array of domain
strings, no auth required for the domain list.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING

from infrastructure.http_client import HttpClient
from infrastructure.logging import get_logger
from repositories.feed_domain_repository import FeedDomainRepository
from services.scheduler.registry import ScheduledTask

if TYPE_CHECKING:
    from config import SafetySettings

log = get_logger(__name__)

FISHFISH_FEED = "fishfish"
FISHFISH_SYNC_TASK = "safety-fishfish-sync"
_FISHFISH_SYNC_CRON = "0 * * * *"

# Operator-curated exact destination domains (the destination-side domain
# blocklist — NOT blocked_domains, which is the custom-domain vanity
# denylist). No sync task: operators add/remove entries directly.
MANUAL_FEED = "manual"

# Shortener chains exist almost exclusively to defeat destination checks —
# is.gd documents the same refusal, and cloak shorteners were spoo.me's
# dominant observed evasion. The seed DATA lives in
# data/shortener_domains.txt (repo-root data/, same home as
# bot_user_agents.txt); it seeds the feed once, then the DB owns the set.
SHORTENER_FEED = "shorteners"
_SHORTENER_SEED_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "data",
    "shortener_domains.txt",
)


def load_shortener_seed() -> tuple[str, ...]:
    """Parse the seed file: one domain per line, ``#`` comments."""
    with open(_SHORTENER_SEED_PATH, encoding="utf-8") as fh:
        return tuple(
            line.strip()
            for line in fh
            if line.strip() and not line.lstrip().startswith("#")
        )


# A feed this small is suspicious (fishfish carries thousands of domains):
# treat it as a bad download rather than a mass delisting, keep the old set.
_FISHFISH_MIN_SANE = 100
_FETCH_TIMEOUT = 30.0


@dataclass(frozen=True)
class FeedSpec:
    """One feed's complete declaration. ``enabled`` receives SafetySettings
    so operator-policy feeds (manual, shorteners) can stay on regardless of
    the SAFETY_ master switch while detection feeds gate on it."""

    name: str
    reason_label: str
    gate: bool
    analyzer: bool
    enabled: Callable[[SafetySettings], bool]
    # L0 wire message for PUBLISHED policies; None keeps the coarse default.
    public_message: str | None = None
    # Scheduler task factory for feeds refreshed from an upstream source.
    sync: (
        Callable[[HttpClient, FeedDomainRepository, SafetySettings], ScheduledTask]
        | None
    ) = None
    # First-boot seed loader; fires only when the feed is empty.
    seed: Callable[[], tuple[str, ...]] | None = None


def _fishfish_task(
    http_client: HttpClient, repo: FeedDomainRepository, settings: SafetySettings
) -> ScheduledTask:
    return fishfish_sync_task(
        FishFishClient(http_client, api_url=settings.fishfish_api_url), repo
    )


FEED_REGISTRY: tuple[FeedSpec, ...] = (
    FeedSpec(
        name=MANUAL_FEED,
        reason_label="the operator blocklist",
        gate=True,
        analyzer=True,
        enabled=lambda s: True,
    ),
    FeedSpec(
        name=SHORTENER_FEED,
        reason_label="a link shortener (redirect chains are refused)",
        gate=True,
        # Gate-only: existing links to shorteners are the deep tier's
        # chain-resolution problem, never a mass-block.
        analyzer=False,
        enabled=lambda s: True,
        public_message="Links to other URL shorteners are not allowed",
        seed=load_shortener_seed,
    ),
    FeedSpec(
        name=FISHFISH_FEED,
        reason_label="fishfish.gg",
        gate=True,
        analyzer=True,
        enabled=lambda s: s.enabled and s.fishfish_enabled,
        sync=_fishfish_task,
    ),
)


def build_feed_providers(
    settings: SafetySettings, repo: FeedDomainRepository
) -> tuple[list, list, dict[str, str]]:
    """Compose (gate_providers, analyzer_providers, public_messages) from
    the registry — the ONLY place feed membership turns into providers, so
    the app wiring and the worker can never drift."""
    from services.safety.providers import FeedDomainProvider

    gate: list = []
    analyzer: list = []
    messages: dict[str, str] = {}
    for spec in FEED_REGISTRY:
        if not spec.enabled(settings):
            continue
        provider = FeedDomainProvider(
            repo, feed=spec.name, reason_label=spec.reason_label
        )
        if spec.gate:
            gate.append(provider)
        if spec.analyzer:
            analyzer.append(provider)
        if spec.public_message:
            messages[provider.name] = spec.public_message
    return gate, analyzer, messages


def build_feed_tasks(
    settings: SafetySettings,
    http_client: HttpClient,
    repo: FeedDomainRepository,
) -> list[ScheduledTask]:
    """Scheduler tasks for every enabled feed that refreshes upstream."""
    return [
        spec.sync(http_client, repo, settings)
        for spec in FEED_REGISTRY
        if spec.sync is not None and spec.enabled(settings)
    ]


async def ensure_feed_seeds(repo: FeedDomainRepository) -> None:
    """First-boot seeds for every feed that declares one — only when that
    feed is EMPTY. Never re-adds afterwards, so an operator removing an
    entry stays removed and deep-tier additions are never clobbered."""
    for spec in FEED_REGISTRY:
        if spec.seed is None:
            continue
        if await repo.count(spec.name) > 0:
            continue
        kept, _ = await repo.replace_feed(spec.name, spec.seed())
        log.info("safety_feed_seeded", feed=spec.name, domains=kept)


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
