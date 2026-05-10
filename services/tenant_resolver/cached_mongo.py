"""Redis-backed Mongo TenantResolver.

Read-through cache with TTL. Negative results (unknown hosts) cached for a
shorter TTL so newly-registered domains become visible quickly. The
system-default host short-circuits before touching Redis or Mongo.
"""

from __future__ import annotations

import json

import redis.asyncio as aioredis
from bson import ObjectId

from infrastructure.logging import get_logger
from repositories.custom_domain_repository import CustomDomainRepository
from schemas.enums.domain_status import DomainStatus
from schemas.models.base import ANONYMOUS_OWNER_ID
from services.tenant_resolver.protocol import TenantInfo, TenantResolver

log = get_logger(__name__)

# Stored as the Redis VALUE under negative-cache keys so a follow-up read
# can distinguish "we already checked and it's unknown" from "no key set".
_NEG_SENTINEL = "__none__"

# Distinct sentinel OBJECTS returned by _cache_get so callers can branch
# between (a) cache miss → must hit Mongo, (b) negative-cached → skip
# Mongo and return None.
_CACHE_MISS = object()
_NEG_CACHE_HIT = object()


class CachedMongoTenantResolver(TenantResolver):
    def __init__(
        self,
        repo: CustomDomainRepository,
        redis_client: aioredis.Redis | None,
        system_default_domain: str,
        positive_ttl_seconds: int = 60,
        # Negative TTL can be aggressive because the orchestrator calls
        # ``invalidate(fqdn)`` on every state transition
        negative_ttl_seconds: int = 300,
    ) -> None:
        self._repo = repo
        self._redis = redis_client
        self._system_default_domain = system_default_domain.lower().rstrip(".")
        self._positive_ttl = positive_ttl_seconds
        self._negative_ttl = negative_ttl_seconds

    def _key(self, host: str) -> str:
        return f"tenant:{host}"

    @staticmethod
    def _normalise_host(host: str) -> str:
        # Strip the optional ``:port`` suffix from a Host header so the cache
        # key matches the stored fqdn regardless of port number.
        return host.split(":")[0].lower().rstrip(".")

    async def resolve(self, host: str) -> TenantInfo | None:
        normalised = self._normalise_host(host)
        if not normalised:
            return None

        # System default short-circuits — no Redis, no Mongo, no cache slot
        # consumed. Hot path stays trivially fast for the dominant case.
        if normalised == self._system_default_domain:
            return TenantInfo(
                domain_id=None,
                fqdn=normalised,
                owner_id=None,
                status=DomainStatus.ACTIVE,
                is_system_default=True,
            )

        cached = await self._cache_get(normalised)
        if cached is _NEG_CACHE_HIT:
            # We already asked Mongo about this host and it didn't exist —
            # short-circuit so scanner traffic / typos don't repeat the query.
            return None
        if cached is not _CACHE_MISS:
            # Positive cache hit — `cached` is the TenantInfo.
            return cached

        doc = await self._repo.find_active_by_fqdn(normalised)
        if doc is None:
            await self._cache_set_negative(normalised)
            return None

        info = TenantInfo(
            domain_id=doc.id,
            fqdn=doc.fqdn,
            owner_id=doc.owner_id
            if doc.owner_id and doc.owner_id != ANONYMOUS_OWNER_ID
            else None,
            status=doc.status,
            is_system_default=bool(doc.is_system_default),
        )
        await self._cache_set(normalised, info)
        return info

    async def invalidate(self, host: str) -> None:
        if self._redis is None:
            return
        normalised = self._normalise_host(host)
        if not normalised or normalised == self._system_default_domain:
            # System default short-circuits resolve(); no cache slot to drop.
            return
        try:
            await self._redis.delete(self._key(normalised))
        except Exception as exc:
            log.warning("tenant_cache_invalidate_error", host=host, error=str(exc))

    # ── Cache helpers ────────────────────────────────────────────────

    async def _cache_get(self, host: str):
        """Return ``_CACHE_MISS``, ``_NEG_CACHE_HIT``, or a ``TenantInfo``.

        Three-state return so resolve() can distinguish "I haven't asked
        yet" from "I already asked and there's nothing" — the latter must
        skip Mongo to be useful as a negative cache.
        """
        if self._redis is None:
            return _CACHE_MISS
        try:
            raw = await self._redis.get(self._key(host))
        except Exception as exc:
            log.warning("tenant_cache_get_error", host=host, error=str(exc))
            return _CACHE_MISS
        if raw is None:
            return _CACHE_MISS
        # Redis client may return bytes or str depending on decode_responses.
        # Normalise to str once so downstream comparisons work either way.
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8", errors="replace")
        if raw == _NEG_SENTINEL:
            return _NEG_CACHE_HIT
        try:
            payload = json.loads(raw)
            return TenantInfo(
                domain_id=ObjectId(payload["domain_id"])
                if payload.get("domain_id")
                else None,
                fqdn=payload["fqdn"],
                owner_id=ObjectId(payload["owner_id"])
                if payload.get("owner_id")
                else None,
                status=DomainStatus(payload["status"]),
                is_system_default=payload.get("is_system_default", False),
            )
        except Exception as exc:
            # Corrupt cache entry — log and treat as a miss so the caller
            # falls through to Mongo and overwrites with fresh data.
            log.warning("tenant_cache_decode_error", host=host, error=str(exc))
            return _CACHE_MISS

    async def _cache_set(self, host: str, info: TenantInfo) -> None:
        if self._redis is None:
            return
        try:
            payload = json.dumps(
                {
                    "domain_id": str(info.domain_id) if info.domain_id else None,
                    "fqdn": info.fqdn,
                    "owner_id": str(info.owner_id) if info.owner_id else None,
                    "status": info.status.value,
                    "is_system_default": info.is_system_default,
                }
            )
            await self._redis.setex(self._key(host), self._positive_ttl, payload)
        except Exception as exc:
            log.warning("tenant_cache_set_error", host=host, error=str(exc))

    async def _cache_set_negative(self, host: str) -> None:
        if self._redis is None:
            return
        try:
            await self._redis.setex(self._key(host), self._negative_ttl, _NEG_SENTINEL)
        except Exception as exc:
            log.warning("tenant_cache_set_negative_error", host=host, error=str(exc))
