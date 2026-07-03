"""Stream history sweeper — trims events every consumer group has finished.

Redis Streams retain entries after XACK (log semantics). The click pipeline
never replays consumed events, so retained history is pure waste: it squats
in the queue Redis's noeviction budget and converts outage-buffer headroom
into dead weight. This sweeper periodically computes the SAFE FLOOR — the
oldest entry that is still pending (delivered, unacked) or undelivered for
ANY group — and trims everything strictly below it via ``XTRIM MINID``.

Safety properties:
- An entry in any group's PEL is never trimmed (it must stay claimable).
- An entry not yet delivered to a lagging group is never trimmed.
- Concurrent sweepers are harmless (XTRIM is monotonic prefix removal).
- Any failure skips the cycle; sweeping is never worth breaking consumption.
"""

from __future__ import annotations

import asyncio
from typing import Any

from infrastructure.logging import get_logger

log = get_logger(__name__)


def _id_sort_key(stream_id: str) -> tuple[int, int]:
    """Stream IDs ("1783108586518-0") compare numerically, not lexically."""
    ms, _, seq = stream_id.partition("-")
    return (int(ms), int(seq or 0))


class StreamTrimmer:
    def __init__(
        self,
        redis_client: Any,
        stream: str,
        interval_seconds: float,
    ) -> None:
        self._redis = redis_client
        self._stream = stream
        self._interval = interval_seconds

    async def run_forever(self) -> None:
        while True:
            try:
                await self.trim_once()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                log.warning(
                    "stream_trim_cycle_failed",
                    stream=self._stream,
                    error=str(exc),
                    error_type=type(exc).__name__,
                )
            await asyncio.sleep(self._interval)

    async def trim_once(self) -> int:
        """Trim fully-consumed history; returns entries removed."""
        floor = await self.safe_floor()
        if floor is None:
            return 0
        removed: int = await self._redis.xtrim(
            self._stream, minid=floor, approximate=False
        )
        if removed:
            log.info(
                "stream_history_trimmed",
                stream=self._stream,
                removed=removed,
                new_floor=floor,
            )
        return removed

    async def safe_floor(self) -> str | None:
        """Oldest ID any group still needs; entries below it are garbage.

        Per group the un-trimmable frontier is:
        - the group's oldest PENDING id, if it has unacked messages, else
        - the id AFTER last-delivered-id (everything ≤ delivered is acked).
        The global floor is the minimum frontier across groups. Returns None
        when there are no groups (nothing consumes → nothing is safe to trim).
        """
        groups = await self._redis.xinfo_groups(self._stream)
        if not groups:
            return None

        frontiers: list[tuple[int, int]] = []
        for group in groups:
            name = group["name"]
            pending_summary = await self._redis.xpending(self._stream, name)
            min_pending = pending_summary.get("min")
            if min_pending:
                frontiers.append(_id_sort_key(min_pending))
                continue
            last_delivered = group.get("last-delivered-id", "0-0")
            ms, seq = _id_sort_key(last_delivered)
            # everything ≤ last-delivered is acked; keep from the next id on
            frontiers.append((ms, seq + 1))

        ms, seq = min(frontiers)
        return f"{ms}-{seq}"
