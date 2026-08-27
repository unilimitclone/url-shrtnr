"""TaskScheduler — the Mongo claim loop that runs registered tasks.

Mongo-only by design (same reasoning as the webhook DeliveryExecutor):
the loop can run in the click worker (prod) or embedded in the app
lifespan (self-host rungs) and N concurrent runners are safe because the
claim is an atomic lease. Poll = clock = claim: comparing the durable
``next_run_at`` against now on every poll IS the scheduling mechanism, so
restarts self-heal and a task that was due during downtime runs once on
the first loop.
"""

from __future__ import annotations

import asyncio
import time
from datetime import datetime, timezone

from infrastructure.logging import get_logger
from repositories.scheduled_task_repository import ScheduledTaskRepository
from schemas.models.scheduled_task import ScheduledTaskDoc, TaskRunResult
from services.scheduler.registry import TaskRegistry, compute_next_run

log = get_logger(__name__)

# last_run.detail is operator-facing breadcrumb, not a payload store.
_DETAIL_MAX = 500


class TaskScheduler:
    def __init__(
        self,
        repo: ScheduledTaskRepository,
        registry: TaskRegistry,
        *,
        poll_interval: float = 5.0,
        lease_seconds: int = 600,
    ) -> None:
        self._repo = repo
        self._registry = registry
        self._poll_interval = poll_interval
        self._lease = lease_seconds

    # ── Loop ─────────────────────────────────────────────────────────────

    async def run(self) -> None:
        """Long-lived task; cancellation is the shutdown path."""
        log.info(
            "task_scheduler_started",
            poll_interval=self._poll_interval,
            tasks=[t.name for t in self._registry.all()],
        )
        # The initial registry sync lives INSIDE the retry loop: a
        # transient Mongo error (or the E11000 two booting processes can
        # race on ensure_task) at boot must retry, not silently kill the
        # scheduler for the process lifetime and then re-raise out of the
        # lifespan's wait_for at shutdown.
        synced = False
        while True:
            try:
                if not synced:
                    await self.sync_registry()
                    synced = True
                row = await self._repo.claim_due(lease_seconds=self._lease)
                if row is None:
                    await asyncio.sleep(self._poll_interval)
                    continue
                await self._execute(row)
            except asyncio.CancelledError:
                log.info("task_scheduler_stopped")
                raise
            except Exception as exc:
                # One bad row must not kill the loop.
                log.error(
                    "task_scheduler_tick_failed",
                    error=str(exc),
                    error_type=type(exc).__name__,
                )
                await asyncio.sleep(self._poll_interval)

    # ── Registry sync ────────────────────────────────────────────────────

    async def sync_registry(self) -> None:
        """Upsert a doc per registration; reconcile code-side schedule
        changes; warn about docs with no registration (never delete — the
        doc may belong to a newer deploy during a rollout overlap)."""
        now = datetime.now(timezone.utc)
        for task in self._registry.all():
            initial_next = compute_next_run(task.schedule, now)
            await self._repo.ensure_task(
                task.name,
                schedule=task.schedule,
                enabled_default=task.enabled_default,
                next_run_at=initial_next,
            )
            changed = await self._repo.reconcile_schedule(
                task.name, schedule=task.schedule, next_run_at=initial_next
            )
            if changed:
                log.info(
                    "task_schedule_reconciled",
                    task=task.name,
                    schedule=task.schedule,
                )
        registered = {t.name for t in self._registry.all()}
        for orphan in await self._repo.list_names() - registered:
            log.warning("task_doc_orphaned", task=orphan)

    # ── One run ──────────────────────────────────────────────────────────

    async def _execute(self, row: ScheduledTaskDoc) -> None:
        name = row.id or ""
        task = self._registry.get(name)
        if task is None:
            # Claimed a doc this process has no handler for (orphan or
            # rollout skew). Release the lease WITHOUT touching
            # next_run_at, so the occurrence is yielded to a process that
            # does know the task rather than consumed: during a deploy
            # overlap the two runners trade claims for a few seconds,
            # bounded by the poll interval, and no run is swallowed.
            log.warning("task_unknown", task=name)
            await self._repo.release_claim(name)
            await asyncio.sleep(self._poll_interval)
            return

        log.info("task_run_started", task=name)
        started = time.monotonic()
        detail: str | None = None
        status = "ok"
        try:
            result = await task.fn()
            if result:
                detail = str(result)[:_DETAIL_MAX]
        except Exception as exc:
            status = "error"
            detail = f"{type(exc).__name__}: {exc}"[:_DETAIL_MAX]
        duration_ms = int((time.monotonic() - started) * 1000)

        # Next occurrence from post-run now: a long run never causes an
        # immediate re-run, and missed windows are never replayed.
        finished_at = datetime.now(timezone.utc)
        await self._repo.finish_run(
            name,
            result=TaskRunResult(
                at=finished_at, status=status, duration_ms=duration_ms, detail=detail
            ),
            next_run_at=compute_next_run(task.schedule, finished_at),
        )
        if status == "ok":
            log.info("task_run_completed", task=name, duration_ms=duration_ms)
        else:
            log.error(
                "task_run_failed", task=name, duration_ms=duration_ms, error=detail
            )
