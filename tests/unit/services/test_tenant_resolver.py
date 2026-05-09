"""Unit tests for CachedMongoTenantResolver."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock

import pytest
from bson import ObjectId

from schemas.enums.domain_status import DomainStatus, VerificationMethod
from schemas.models.custom_domain import CustomDomainDoc
from services.tenant_resolver.cached_mongo import CachedMongoTenantResolver


def _doc(fqdn="links.acme.com"):
    return CustomDomainDoc(
        id=ObjectId(),
        fqdn=fqdn,
        owner_id=ObjectId(),
        status=DomainStatus.ACTIVE,
        verification_method=VerificationMethod.CNAME,
        created_at=datetime.now(timezone.utc),
    )


class TestCachedMongoTenantResolver:
    @pytest.mark.asyncio
    async def test_system_host_short_circuits_no_redis_no_repo(self):
        repo = AsyncMock()
        redis = AsyncMock()
        r = CachedMongoTenantResolver(repo, redis, system_default_domain="spoo.me")

        info = await r.resolve("spoo.me")
        assert info is not None
        assert info.is_system_default is True
        assert info.fqdn == "spoo.me"
        # Hot path: no Redis, no Mongo.
        redis.get.assert_not_called()
        repo.find_active_by_fqdn.assert_not_called()

    @pytest.mark.asyncio
    async def test_strips_port_from_host_header(self):
        repo = AsyncMock()
        redis = None
        r = CachedMongoTenantResolver(repo, redis, system_default_domain="spoo.me")
        info = await r.resolve("spoo.me:8000")
        assert info is not None
        assert info.is_system_default is True

    @pytest.mark.asyncio
    async def test_unknown_host_negatives_cached(self):
        repo = AsyncMock()
        repo.find_active_by_fqdn = AsyncMock(return_value=None)
        redis = AsyncMock()
        redis.get = AsyncMock(return_value=None)
        r = CachedMongoTenantResolver(repo, redis, system_default_domain="spoo.me")

        info = await r.resolve("links.example.com")
        assert info is None
        redis.setex.assert_awaited()
        # Negative sentinel should be the value
        args, _ = redis.setex.call_args
        assert args[2] == "__none__"

    @pytest.mark.asyncio
    async def test_redis_hit_skips_mongo(self):
        repo = AsyncMock()
        d = _doc()
        payload = json.dumps(
            {
                "domain_id": str(d.id),
                "fqdn": d.fqdn,
                "owner_id": str(d.owner_id),
                "status": d.status.value,
                "is_system_default": False,
            }
        )
        redis = AsyncMock()
        redis.get = AsyncMock(return_value=payload)
        r = CachedMongoTenantResolver(repo, redis, system_default_domain="spoo.me")

        info = await r.resolve("links.acme.com")
        assert info is not None
        assert info.fqdn == "links.acme.com"
        repo.find_active_by_fqdn.assert_not_called()

    @pytest.mark.asyncio
    async def test_mongo_miss_populates_redis(self):
        d = _doc()
        repo = AsyncMock()
        repo.find_active_by_fqdn = AsyncMock(return_value=d)
        redis = AsyncMock()
        redis.get = AsyncMock(return_value=None)
        r = CachedMongoTenantResolver(repo, redis, system_default_domain="spoo.me")

        info = await r.resolve("links.acme.com")
        assert info is not None
        assert info.fqdn == "links.acme.com"
        redis.setex.assert_awaited()
        args, _ = redis.setex.call_args
        # Stored value should be JSON, not the negative sentinel.
        assert args[2] != "__none__"
        decoded = json.loads(args[2])
        assert decoded["fqdn"] == "links.acme.com"

    @pytest.mark.asyncio
    async def test_tolerates_redis_none(self):
        d = _doc()
        repo = AsyncMock()
        repo.find_active_by_fqdn = AsyncMock(return_value=d)
        r = CachedMongoTenantResolver(
            repo, redis_client=None, system_default_domain="spoo.me"
        )

        info = await r.resolve("links.acme.com")
        assert info is not None
        assert info.fqdn == "links.acme.com"

    @pytest.mark.asyncio
    async def test_corrupt_cache_falls_through_to_mongo(self):
        d = _doc()
        repo = AsyncMock()
        repo.find_active_by_fqdn = AsyncMock(return_value=d)
        redis = AsyncMock()
        redis.get = AsyncMock(return_value="not-json")
        r = CachedMongoTenantResolver(repo, redis, system_default_domain="spoo.me")

        info = await r.resolve("links.acme.com")
        assert info is not None
        repo.find_active_by_fqdn.assert_awaited_once()
