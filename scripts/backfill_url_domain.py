"""One-shot migration: stamp ``domain`` on every urlsV2 doc missing it.

Run once when upgrading to the custom-domains release. Idempotent — re-runs
match zero docs.

Usage::

    uv run python -m scripts.backfill_url_domain
"""

from __future__ import annotations

import asyncio

from pymongo.asynchronous.mongo_client import AsyncMongoClient

from config import AppSettings


async def main() -> None:
    settings = AppSettings()
    client: AsyncMongoClient = AsyncMongoClient(settings.db.mongodb_uri)
    db = client[settings.db.db_name]

    fqdn = settings.system_default_domain
    needs = await db["urlsV2"].count_documents(
        {"$or": [{"domain": {"$exists": False}}, {"domain": ""}]}
    )
    print(f"Docs needing backfill: {needs}")

    if needs == 0:
        print("Nothing to do.")
        await client.close()
        return

    result = await db["urlsV2"].update_many(
        {"$or": [{"domain": {"$exists": False}}, {"domain": ""}]},
        {"$set": {"domain": fqdn}},
    )
    print(f"Stamped domain={fqdn!r} on {result.modified_count} docs.")

    remaining = await db["urlsV2"].count_documents(
        {"$or": [{"domain": {"$exists": False}}, {"domain": ""}]}
    )
    print(f"Remaining un-stamped (expect 0): {remaining}")

    await client.close()


if __name__ == "__main__":
    asyncio.run(main())
