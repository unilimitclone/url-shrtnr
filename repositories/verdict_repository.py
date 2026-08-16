"""Repository for the ``safety_verdicts`` collection.

Verdicts are upserted by host: re-analysis refreshes the existing doc
rather than accumulating history (run history lives in logs). Reads are
point lookups on the unique host index.
"""

from __future__ import annotations

from datetime import datetime, timezone

from repositories.base import BaseRepository
from schemas.enums.safety import VerdictTier
from schemas.models.verdict import VerdictDoc


class VerdictRepository(BaseRepository[VerdictDoc]):
    async def upsert_verdict(
        self,
        host: str,
        *,
        registrable_domain: str,
        tier: VerdictTier,
        reason: str | None,
        source: str,
        trigger: str,
        sample_url: str | None = None,
        context: dict | None = None,
        decided_by: str = "system",
    ) -> None:
        now = datetime.now(timezone.utc)
        await self._col.update_one(
            {"host": host},
            {
                "$set": {
                    "registrable_domain": registrable_domain,
                    "tier": tier.value,
                    "reason": reason,
                    "source": source,
                    "trigger": trigger,
                    "sample_url": sample_url,
                    "context": context,
                    "decided_by": decided_by,
                    "updated_at": now,
                },
                "$setOnInsert": {"created_at": now},
            },
            upsert=True,
        )

    async def find_by_host(self, host: str) -> VerdictDoc | None:
        return await self._find_one({"host": host})
