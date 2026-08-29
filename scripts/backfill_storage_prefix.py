#!/usr/bin/env -S uv run --script

# PEP 723 metadata so this runs standalone via `uv run --script` (keep)
# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "pymongo>=4.6",
# ]
# ///
"""One-shot migration: pin ``storage_prefix`` on users with existing uploads.

Upload paths pin the R2 owner-key prefix at FIRST upload; accounts whose
objects predate the field have nothing stored, so the erasure sweep
recomputes their prefix from the CURRENT secret. Run this BEFORE any
SECRET_KEY rotation to be meaningful — after a rotation the prefix the
objects actually live under can no longer be recomputed, and they orphan.

Targets users with a profile picture (``pfp`` set) and no pinned prefix.
The derivation mirrors ``services/image_ingest.owner_key_prefix`` exactly:
HMAC-SHA256(SECRET_KEY, str(user_id)), first 16 hex chars.

Standalone — no spoo project context required. Run anywhere uv is installed.

Reads ``MONGODB_URI``, ``SECRET_KEY``, and (optional) ``DB_NAME`` from the
environment. Pass ``--env-file`` to ``uv run`` to load a dotenv file.

Usage::

    # apply
    uv run --env-file .env.production scripts/backfill_storage_prefix.py

    # preview only
    uv run --env-file .env.production scripts/backfill_storage_prefix.py --dry-run
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import os
import sys

from pymongo import MongoClient, UpdateOne
from pymongo.errors import PyMongoError

# {"storage_prefix": None} matches both a null field and a missing one.
_FILTER = {"pfp": {"$ne": None}, "storage_prefix": None}

_BATCH_SIZE = 500


def _owner_key_prefix(user_id, secret: str) -> str:
    digest = hmac.new(secret.encode(), str(user_id).encode(), hashlib.sha256)
    return digest.hexdigest()[:16]


def _flush(coll, batch, stamped: int, failed: int) -> tuple[int, int]:
    # Rerun-safe: the storage_prefix None filter skips anything stamped.
    try:
        return stamped + coll.bulk_write(batch).modified_count, failed
    except PyMongoError as exc:
        print(f"batch of {len(batch)} failed ({exc}); continuing", file=sys.stderr)
        return stamped, failed + 1


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show counts without writing.",
    )
    args = parser.parse_args()

    mongodb_uri = os.environ.get("MONGODB_URI")
    secret_key = os.environ.get("SECRET_KEY")
    db_name = os.environ.get("DB_NAME", "url-shortener")

    if not mongodb_uri:
        sys.exit("MONGODB_URI not set in environment.")
    if not secret_key:
        sys.exit("SECRET_KEY not set in environment.")

    client: MongoClient = MongoClient(mongodb_uri)
    coll = client[db_name]["users"]

    needs = coll.count_documents(_FILTER)
    print(f"Users needing backfill: {needs}")

    if needs == 0:
        print("Nothing to do.")
        client.close()
        return

    if args.dry_run:
        print("DRY RUN — no writes performed.")
        client.close()
        return

    stamped = 0
    failed_batches = 0
    batch: list[UpdateOne] = []
    for doc in coll.find(_FILTER, projection={"_id": 1}):
        user_id = doc["_id"]
        batch.append(
            UpdateOne(
                # Re-guarded per doc: a concurrent first upload pinning the
                # prefix mid-run must win (same guard as the app's repo).
                {"_id": user_id, "storage_prefix": None},
                {"$set": {"storage_prefix": _owner_key_prefix(user_id, secret_key)}},
            )
        )
        if len(batch) >= _BATCH_SIZE:
            stamped, failed_batches = _flush(coll, batch, stamped, failed_batches)
            batch = []
    if batch:
        stamped, failed_batches = _flush(coll, batch, stamped, failed_batches)

    print(f"Stamped storage_prefix on {stamped} users.")
    if failed_batches:
        print(f"{failed_batches} batch(es) failed transiently; rerun to finish.")

    remaining = coll.count_documents(_FILTER)
    print(f"Remaining un-stamped (expect 0): {remaining}")

    client.close()
    if failed_batches:
        sys.exit(1)


if __name__ == "__main__":
    main()
