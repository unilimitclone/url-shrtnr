#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "pymongo>=4.6",
# ]
# ///
"""One-shot migration: stamp ``domain`` on every urlsV2 doc missing it.

Standalone — no spoo project context required. Run anywhere uv is installed.

Reads ``MONGODB_URI``, ``APP_URL``, and (optional) ``DB_NAME`` from the
environment. Pass ``--env-file`` to ``uv run`` to load a dotenv file.

Usage::

    # apply
    uv run --env-file .env.production scripts/backfill_url_domain.py

    # preview only
    uv run --env-file .env.production scripts/backfill_url_domain.py --dry-run
"""

from __future__ import annotations

import argparse
import os
import sys
from urllib.parse import urlparse

from pymongo import MongoClient

_FILTER = {"$or": [{"domain": {"$exists": False}}, {"domain": ""}]}


def _system_default_domain(app_url: str) -> str:
    parsed = urlparse(app_url)
    if not parsed.scheme or not parsed.hostname:
        sys.exit(
            f"APP_URL is missing or invalid: {app_url!r}. "
            "Set APP_URL to your shortener's public URL (e.g. https://spoo.me)."
        )
    return parsed.hostname.lower().rstrip(".")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show counts and target domain without writing.",
    )
    args = parser.parse_args()

    mongodb_uri = os.environ.get("MONGODB_URI")
    app_url = os.environ.get("APP_URL")
    db_name = os.environ.get("DB_NAME", "url-shortener")

    if not mongodb_uri:
        sys.exit("MONGODB_URI not set in environment.")
    if not app_url:
        sys.exit("APP_URL not set in environment.")

    fqdn = _system_default_domain(app_url)
    client: MongoClient = MongoClient(mongodb_uri)
    coll = client[db_name]["urlsV2"]

    needs = coll.count_documents(_FILTER)
    print(f"Docs needing backfill: {needs}")
    print(f"Would stamp domain={fqdn!r}")

    if needs == 0:
        print("Nothing to do.")
        client.close()
        return

    if args.dry_run:
        print("DRY RUN — no writes performed.")
        client.close()
        return

    result = coll.update_many(_FILTER, {"$set": {"domain": fqdn}})
    print(f"Stamped domain={fqdn!r} on {result.modified_count} docs.")

    remaining = coll.count_documents(_FILTER)
    print(f"Remaining un-stamped (expect 0): {remaining}")

    client.close()


if __name__ == "__main__":
    main()
