"""One-shot migration: stamp ``domain`` on every urlsV2 doc missing it.

Run once when upgrading to the custom-domains release. Idempotent — re-runs
match zero docs.

Usage::

    uv run python -m scripts.backfill_url_domain               # apply
    uv run python -m scripts.backfill_url_domain --dry-run     # preview only
"""

from __future__ import annotations

import argparse
import asyncio

from pymongo.asynchronous.mongo_client import AsyncMongoClient

from config import AppSettings

_FILTER = {"$or": [{"domain": {"$exists": False}}, {"domain": ""}]}


async def run(dry_run: bool) -> None:
    settings = AppSettings()
    client: AsyncMongoClient = AsyncMongoClient(settings.db.mongodb_uri)
    db = client[settings.db.db_name]

    fqdn = settings.system_default_domain
    needs = await db["urlsV2"].count_documents(_FILTER)
    print(f"Docs needing backfill: {needs}")
    print(f"Would stamp domain={fqdn!r}")

    if needs == 0:
        print("Nothing to do.")
        await client.close()
        return

    if dry_run:
        print("DRY RUN — no writes performed.")
        await client.close()
        return

    result = await db["urlsV2"].update_many(_FILTER, {"$set": {"domain": fqdn}})
    print(f"Stamped domain={fqdn!r} on {result.modified_count} docs.")

    remaining = await db["urlsV2"].count_documents(_FILTER)
    print(f"Remaining un-stamped (expect 0): {remaining}")

    await client.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show counts and target domain without writing.",
    )
    args = parser.parse_args()
    asyncio.run(run(dry_run=args.dry_run))


if __name__ == "__main__":
    main()
