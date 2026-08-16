"""Unit tests for ScheduledTaskRepository — claim/lease semantics."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest
from pymongo import ReturnDocument

from repositories.scheduled_task_repository import ScheduledTaskRepository
from schemas.models.scheduled_task import TaskRunResult


def _col() -> AsyncMock:
    col = AsyncMock()
    col.name = "scheduled_tasks"
    return col


class TestEnsureTask:
    @pytest.mark.asyncio
    async def test_upserts_with_set_on_insert_only(self):
        col = _col()
        repo = ScheduledTaskRepository(col)
        nxt = datetime(2026, 8, 17, 11, 0, tzinfo=timezone.utc)

        await repo.ensure_task(
            "feed-sync", schedule="0 * * * *", enabled_default=True, next_run_at=nxt
        )

        args, kwargs = col.update_one.await_args
        assert args[0] == {"_id": "feed-sync"}
        assert kwargs["upsert"] is True
        soi = args[1]["$setOnInsert"]
        assert soi["schedule"] == "0 * * * *"
        assert soi["next_run_at"] == nxt
        assert soi["enabled"] is True
        assert soi["claimed_until"] is None
        # Runtime state must never be clobbered on existing docs.
        assert "$set" not in args[1]


class TestClaimDue:
    @pytest.mark.asyncio
    async def test_claim_query_shape_and_lease(self):
        col = _col()
        col.find_one_and_update = AsyncMock(return_value=None)
        repo = ScheduledTaskRepository(col)

        before = datetime.now(timezone.utc)
        assert await repo.claim_due(lease_seconds=600) is None

        args, kwargs = col.find_one_and_update.await_args
        query, update = args
        assert query["enabled"] is True
        assert "$lte" in query["next_run_at"]
        assert {"claimed_until": None} in query["$or"]
        lease = update["$set"]["claimed_until"]
        assert lease >= before + timedelta(seconds=599)
        assert kwargs["sort"] == [("next_run_at", 1)]
        assert kwargs["return_document"] == ReturnDocument.AFTER

    @pytest.mark.asyncio
    async def test_claim_returns_doc_model(self):
        col = _col()
        col.find_one_and_update = AsyncMock(
            return_value={
                "_id": "feed-sync",
                "schedule": "0 * * * *",
                "enabled": True,
                "next_run_at": datetime.now(timezone.utc),
            }
        )
        repo = ScheduledTaskRepository(col)
        doc = await repo.claim_due(lease_seconds=60)
        assert doc is not None
        assert doc.id == "feed-sync"


class TestFinishRun:
    @pytest.mark.asyncio
    async def test_records_result_and_releases_lease(self):
        col = _col()
        repo = ScheduledTaskRepository(col)
        result = TaskRunResult(
            at=datetime.now(timezone.utc), status="ok", duration_ms=42, detail=None
        )
        nxt = datetime.now(timezone.utc) + timedelta(hours=1)

        await repo.finish_run("feed-sync", result=result, next_run_at=nxt)

        args, _ = col.update_one.await_args
        assert args[0] == {"_id": "feed-sync"}
        st = args[1]["$set"]
        assert st["last_run"]["status"] == "ok"
        assert st["next_run_at"] == nxt
        assert st["claimed_until"] is None


class TestInvokeNow:
    @pytest.mark.asyncio
    async def test_arms_next_run_at(self):
        col = _col()
        col.update_one = AsyncMock(return_value=MagicMock(modified_count=1))
        repo = ScheduledTaskRepository(col)
        assert await repo.invoke_now("feed-sync") is True
        args, _ = col.update_one.await_args
        assert args[0] == {"_id": "feed-sync"}
        assert "next_run_at" in args[1]["$set"]

    @pytest.mark.asyncio
    async def test_unknown_task_returns_false(self):
        col = _col()
        col.update_one = AsyncMock(return_value=MagicMock(modified_count=0))
        repo = ScheduledTaskRepository(col)
        assert await repo.invoke_now("nope") is False


class TestReconcileSchedule:
    @pytest.mark.asyncio
    async def test_updates_only_when_schedule_differs(self):
        col = _col()
        col.update_one = AsyncMock(return_value=MagicMock(modified_count=0))
        repo = ScheduledTaskRepository(col)
        changed = await repo.reconcile_schedule(
            "feed-sync", schedule="0 * * * *", next_run_at=None
        )
        assert changed is False
        args, _ = col.update_one.await_args
        # Guarded update: the filter excludes docs already carrying the schedule.
        assert args[0] == {"_id": "feed-sync", "schedule": {"$ne": "0 * * * *"}}
