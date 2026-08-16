"""SafetyEnforcer — turns a toxic verdict into reality, everywhere at once.

Order matters: collect the invalidation set first (the status flip removes
docs from the ACTIVE filter), then flip, then evict Redis + edge so the
next click rebuilds from Mongo and serves the 451. Owned links emit
link.blocked domain events (anonymous links have no possible webhook
subscriber). v1/emoji links have no status field — they are counted and
surfaced to the operator, never auto-deleted.

Idempotent by construction: re-enforcing an already-blocked host matches
nothing and is free, which is what lets repeat reports re-run enforcement
instead of reasoning about state.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from infrastructure.cache.url_cache import UrlCache
from infrastructure.cloudflare_kv import CloudflareKVClient
from infrastructure.logging import get_logger
from repositories.legacy.emoji_url_repository import EmojiUrlRepository
from repositories.legacy.legacy_url_repository import LegacyUrlRepository
from repositories.url_repository import UrlRepository
from schemas.models.url import UrlStatus
from services.edge_cache.contract import cache_key
from services.events.contract import DomainEvent
from services.events.protocol import DomainEventSink
from services.webhooks.payloads import link_owner_id, link_snapshot

log = get_logger(__name__)


@dataclass(frozen=True)
class EnforcementResult:
    host: str
    blocked_count: int
    legacy_count: int
    cache_invalidated: int


class SafetyEnforcer:
    def __init__(
        self,
        url_repo: UrlRepository,
        legacy_repo: LegacyUrlRepository,
        emoji_repo: EmojiUrlRepository,
        url_cache: UrlCache,
        *,
        events: DomainEventSink | None = None,
        edge_kv: CloudflareKVClient | None = None,
        system_default_domain: str = "spoo.me",
    ) -> None:
        self._url_repo = url_repo
        self._legacy_repo = legacy_repo
        self._emoji_repo = emoji_repo
        self._url_cache = url_cache
        self._events = events
        self._edge_kv = edge_kv
        self._system_domain = system_default_domain

    async def block_host(self, host: str, *, reason: str) -> EnforcementResult:
        # 1. Collect BEFORE the flip: the invalidation set and the owned
        #    docs for events both filter on status ACTIVE.
        pairs = await self._url_repo.list_active_alias_domain_by_dest_host(host)
        owned = await self._url_repo.list_active_owned_by_dest_host(host)

        # 2. Flip.
        blocked = await self._url_repo.block_active_by_dest_host(host)

        # 3. Evict Redis per domain namespace.
        by_domain: dict[str, list[str]] = defaultdict(list)
        for alias, domain in pairs:
            by_domain[domain or self._system_domain].append(alias)
        for domain, aliases in by_domain.items():
            await self._url_cache.invalidate_many(aliases, domain)

        # 4. Evict edge KV (system domain only — tenant domains never
        #    promote). Best-effort: the client returns bool, never raises.
        if self._edge_kv is not None:
            system_aliases = by_domain.get(self._system_domain, [])
            if system_aliases:
                await self._edge_kv.bulk_delete(
                    [cache_key(self._system_domain, a) for a in system_aliases]
                )

        # 5. link.blocked for owned links; sink never raises.
        if self._events is not None:
            for doc in owned:
                owner = link_owner_id(doc)
                if owner is None:
                    continue
                snapshot_doc = doc.model_copy(update={"status": UrlStatus.BLOCKED})
                await self._events.emit(
                    DomainEvent(
                        type="link.blocked",
                        owner_id=owner,
                        data={"link": link_snapshot(snapshot_doc), "reason": reason},
                    )
                )

        # 6. v1 exposure is surfaced, not auto-deleted.
        legacy = await self._legacy_repo.count_by_dest_host(host)
        legacy += await self._emoji_repo.count_by_dest_host(host)

        log.info(
            "safety_host_blocked",
            host=host,
            blocked_count=blocked,
            legacy_count=legacy,
            cache_invalidated=len(pairs),
            reason=reason,
        )
        return EnforcementResult(
            host=host,
            blocked_count=blocked,
            legacy_count=legacy,
            cache_invalidated=len(pairs),
        )
