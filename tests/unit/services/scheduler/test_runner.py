"""Unit tests for TaskScheduler — sync, execute, failure isolation."""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock

import pytest

from schemas.models.scheduled_task import ScheduledTaskDoc
from services.scheduler.registry import ScheduledTask, TaskRegistry
from services.scheduler.runner import TaskScheduler


def _repo() -> AsyncMock:
    repo = AsyncMock()
    repo.list_names = AsyncMock(return_value=set())
    repo.reconcile_schedule = AsyncMock(return_value=False)
    return repo


def _row(name: str, schedule: str | None = "0 * * * *") -> ScheduledTaskDoc:
    return ScheduledTaskDoc(
        _id=name,
        schedule=schedule,
        enabled=True,
        next_run_at=datetime.now(timezone.utc),
    )


class TestSyncRegistry:
    @pytest.mark.asyncio
    async def test_upserts_every_registration(self):
        reg = TaskRegistry()

        async def fn() -> dict | None:
            return None

        reg.register(ScheduledTask(name="a", fn=fn, schedule="0 * * * *"))
        reg.register(ScheduledTask(name="b", fn=fn, schedule=None))
        repo = _repo()

        await TaskScheduler(repo, reg).sync_registry()

        names = [c.args[0] for c in repo.ensure_task.await_args_list]
        assert names == ["a", "b"]
        # Manual-only task is armed with next_run_at=None.
        b_kwargs = repo.ensure_task.await_args_list[1].kwargs
        assert b_kwargs["next_run_at"] is None

    @pytest.mark.asyncio
    async def test_orphan_docs_logged_not_deleted(self):
        reg = TaskRegistry()
        repo = _repo()
        repo.list_names = AsyncMock(return_value={"ghost"})

        await TaskScheduler(repo, reg).sync_registry()

        repo.delete_by_id.assert_not_awaited()


class TestExecute:
    @pytest.mark.asyncio
    async def test_success_records_ok_and_next_run(self):
        reg = TaskRegistry()
        calls = []

        async def fn() -> dict | None:
            calls.append(1)
            return {"synced": 3}

        reg.register(ScheduledTask(name="feed-sync", fn=fn, schedule="0 * * * *"))
        repo = _repo()
        sched = TaskScheduler(repo, reg)

        await sched._execute(_row("feed-sync"))

        assert calls == [1]
        kwargs = repo.finish_run.await_args.kwargs
        assert kwargs["result"].status == "ok"
        assert "synced" in (kwargs["result"].detail or "")
        assert kwargs["next_run_at"] is not None
        assert kwargs["next_run_at"] > datetime.now(timezone.utc)

    @pytest.mark.asyncio
    async def test_handler_exception_recorded_not_raised(self):
        reg = TaskRegistry()

        async def fn() -> dict | None:
            raise RuntimeError("feed 500")

        reg.register(ScheduledTask(name="feed-sync", fn=fn, schedule="0 * * * *"))
        repo = _repo()

        await TaskScheduler(repo, reg)._execute(_row("feed-sync"))

        kwargs = repo.finish_run.await_args.kwargs
        assert kwargs["result"].status == "error"
        assert "RuntimeError" in kwargs["result"].detail
        # A failed run still re-arms the next occurrence.
        assert kwargs["next_run_at"] is not None

    @pytest.mark.asyncio
    async def test_manual_only_task_rearms_to_none(self):
        reg = TaskRegistry()

        async def fn() -> dict | None:
            return None

        reg.register(ScheduledTask(name="manual", fn=fn, schedule=None))
        repo = _repo()

        await TaskScheduler(repo, reg)._execute(_row("manual", schedule=None))

        assert repo.finish_run.await_args.kwargs["next_run_at"] is None

    @pytest.mark.asyncio
    async def test_unknown_task_finishes_with_error_and_stored_schedule(self):
        repo = _repo()
        await TaskScheduler(repo, TaskRegistry())._execute(_row("ghost"))

        kwargs = repo.finish_run.await_args.kwargs
        assert kwargs["result"].status == "error"
        # Re-armed from the STORED schedule so a knowing process can claim it.
        assert kwargs["next_run_at"] is not None
