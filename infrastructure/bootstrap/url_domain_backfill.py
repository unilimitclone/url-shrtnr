"""Backfill ``domain`` on every ``urlsV2`` doc missing the field.

Idempotent — matches zero docs after the first successful run. Must run
before the compound ``{domain, alias}`` unique index is built (otherwise
the index build fails on docs without the field).
"""

from __future__ import annotations

from pymongo.asynchronous.database import AsyncDatabase

from infrastructure.logging import get_logger

log = get_logger(__name__)


async def backfill_url_domain(db: AsyncDatabase, default_domain: str) -> int:
    """Set ``domain`` on every urlsV2 doc missing it. Returns count updated."""
    result = await db["urlsV2"].update_many(
        {"$or": [{"domain": {"$exists": False}}, {"domain": ""}]},
        {"$set": {"domain": default_domain}},
    )
    if result.modified_count:
        log.info(
            "url_domain_backfilled",
            default_domain=default_domain,
            modified=result.modified_count,
        )
    return result.modified_count
