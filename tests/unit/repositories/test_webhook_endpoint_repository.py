"""Pending-slot counter on the endpoint document: the reserve is a single
conditional update (the cap is enforced by Mongo, not by a read), the
release floors at zero, and the repair overwrite reports what it replaced."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from bson import ObjectId

from repositories.webhook_endpoint_repository import WebhookEndpointRepository

from .conftest import make_collection

_EP = ObjectId("eeeeeeeeeeeeeeeeeeeeeeee")


def _repo():
    col = make_collection()
    return WebhookEndpointRepository(col), col


class TestPendingCounter:
    @pytest.mark.asyncio
    async def test_reserve_is_one_conditional_increment(self):
        repo, col = _repo()
        col.update_one.return_value = MagicMock(matched_count=1)
        assert await repo.reserve_pending(_EP, 1000) is True
        query, ops = col.update_one.await_args[0]
        assert query == {"_id": _EP, "pending_count": {"$lt": 1000}}
        assert ops == {"$inc": {"pending_count": 1, "total_deliveries": 1}}
        col.count_documents.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_reserve_at_cap_is_refused(self):
        repo, col = _repo()
        col.update_one.return_value = MagicMock(matched_count=0)
        assert await repo.reserve_pending(_EP, 1000) is False

    @pytest.mark.asyncio
    async def test_release_never_goes_negative(self):
        repo, col = _repo()
        col.update_one.return_value = MagicMock(matched_count=0)
        await repo.release_pending(_EP)
        query, ops = col.update_one.await_args[0]
        assert query == {"_id": _EP, "pending_count": {"$gt": 0}}
        assert ops == {"$inc": {"pending_count": -1}}

    @pytest.mark.asyncio
    async def test_set_pending_count_returns_previous(self):
        repo, col = _repo()
        col.find_one_and_update.return_value = {"_id": _EP, "pending_count": 4200}
        assert await repo.set_pending_count(_EP, 17) == 4200
        query, ops = col.find_one_and_update.await_args[0]
        assert query == {"_id": _EP}
        assert ops == {"$set": {"pending_count": 17}}

    @pytest.mark.asyncio
    async def test_set_pending_count_missing_field_reads_as_zero(self):
        repo, col = _repo()
        col.find_one_and_update.return_value = {"_id": _EP}
        assert await repo.set_pending_count(_EP, 3) == 0
