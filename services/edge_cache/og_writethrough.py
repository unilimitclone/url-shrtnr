"""Eager KV write-through for custom meta-tags (edge-first serving).

On every meta-relevant write, origin renders the OG page once and puts an
``og_only`` entry in Workers KV so the edge answers preview bots with zero
origin round-trips. Humans always pass through (the worker only serves
``og_only`` entries to preview crawlers), so click tracking is unaffected.

Lifecycle (event-driven, no TTL):
  - meta set / meta edited / long_url or status/alias/domain changed on an
    og-link → re-render + put (or delete when no longer eligible)
  - meta cleared / link deleted / status not ACTIVE → delete

Best-effort by contract, like promotion: a KV outage must never fail a
user's API write — worst case bots reach origin, which answers correctly.

Scope: system-domain v2 links only. Custom-domain tenants never route
through the worker (CF-for-SaaS), so KV entries for them would be dead
weight; origin serves their previews directly.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from infrastructure.logging import get_logger
from schemas.models.url import UrlStatus
from services.edge_cache.contract import EdgeCacheEntry, cache_key
from services.edge_cache.render import render_meta_preview

if TYPE_CHECKING:
    from infrastructure.cache.url_cache import UrlCacheData
    from infrastructure.cloudflare_kv import CloudflareKVClient

log = get_logger(__name__)


class OgEdgeWritethrough:
    def __init__(self, kv: CloudflareKVClient, *, system_domain: str) -> None:
        self._kv = kv
        self._system_domain = system_domain

    async def sync(self, url: UrlCacheData) -> None:
        """Reconcile the KV og entry with the link's current state.

        Callers invoke this only for links that have meta_tags now or had
        them before the write — never for plain links, whose promoted
        redirect entries must not be touched.
        """
        if url.domain != self._system_domain:
            return
        key = cache_key(url.domain, url.alias)
        try:
            if url.meta_title is not None and url.url_status == UrlStatus.ACTIVE:
                entry = EdgeCacheEntry(type="og_only", og_html=render_meta_preview(url))
                ok = await self._kv.put(key, entry.to_kv_json())
                log.info(
                    "og_writethrough_put",
                    short_code=url.alias,
                    domain=url.domain,
                    ok=ok,
                )
            else:
                # Cleared / inactive / blocked: drop the whole key. If the
                # link was also hot-promoted this wipes its redirect entry
                # too — it re-promotes within one hotness window.
                ok = await self._kv.delete(key)
                log.info(
                    "og_writethrough_delete",
                    short_code=url.alias,
                    domain=url.domain,
                    ok=ok,
                )
        except Exception:
            log.exception(
                "og_writethrough_failed", short_code=url.alias, domain=url.domain
            )

    async def remove(self, domain: str, alias: str) -> None:
        """Drop the entry for a deleted/renamed/moved og-link (old key)."""
        if domain != self._system_domain:
            return
        try:
            await self._kv.delete(cache_key(domain, alias))
            log.info("og_writethrough_delete", short_code=alias, domain=domain, ok=True)
        except Exception:
            log.exception("og_writethrough_failed", short_code=alias, domain=domain)
