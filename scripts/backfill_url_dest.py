#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "pymongo>=4.6",
#     "tldextract>=5.1",
# ]
# ///
"""One-shot migration: stamp parsed `dest` parts on every url doc missing it.

Covers urlsV2 (long_url), urls (url) and emojis (url). Standalone — no spoo
project context required. Parse logic mirrors
``shared/url_utils.parse_destination`` — keep the two in sync.

Unparseable destinations are stamped ``dest: null`` so the needs-backfill
filter converges to zero; null adds nothing to the sparse dest_registrable
index.

Usage::

    # preview only
    uv run --env-file .env.production scripts/backfill_url_dest.py --dry-run

    # apply
    uv run --env-file .env.production scripts/backfill_url_dest.py
"""

from __future__ import annotations

import argparse
import contextlib
import os
import sys
from urllib.parse import urlsplit

import tldextract
from pymongo import MongoClient, UpdateOne

_FILTER = {"dest": {"$exists": False}}
_BATCH = 1_000
_COLLECTIONS = (("urlsV2", "long_url"), ("urls", "url"), ("emojis", "url"))
_tld = tldextract.TLDExtract(cache_dir=None)


def parse_destination(url: object) -> dict | None:
    """Mirror of shared/url_utils.parse_destination — keep in sync."""
    if not url or not isinstance(url, str):
        return None
    try:
        parsed = urlsplit(url)
        host = parsed.hostname
    except ValueError:
        return None
    if not host:
        return None
    host = host.rstrip(".").lower()
    if not host:
        return None
    if any(ord(ch) > 127 for ch in host):
        with contextlib.suppress(UnicodeError):
            host = host.encode("idna").decode("ascii")
    ext = _tld(host)
    if ext.suffix:
        registrable, subdomain = f"{ext.domain}.{ext.suffix}", ext.subdomain
    else:
        registrable, subdomain = host, ""
    return {
        "scheme": parsed.scheme.lower(),
        "host": host,
        "subdomain": subdomain,
        "registrable_domain": registrable,
    }


def backfill(coll, url_field: str, dry_run: bool) -> None:
    todo = coll.count_documents(_FILTER)
    print(f"[{coll.name}] docs needing backfill: {todo}")
    if todo == 0:
        return
    if dry_run:
        sample = coll.find_one(_FILTER, {url_field: 1})
        print(
            f"[{coll.name}] sample parse: "
            f"{parse_destination((sample or {}).get(url_field))}"
        )
        return
    done = 0
    while True:
        batch = list(coll.find(_FILTER, {url_field: 1}).limit(_BATCH))
        if not batch:
            break
        ops = [
            UpdateOne(
                {"_id": d["_id"]},
                {"$set": {"dest": parse_destination(d.get(url_field))}},
            )
            for d in batch
        ]
        coll.bulk_write(ops, ordered=False)
        done += len(batch)
        if done % 50_000 < _BATCH:
            print(f"[{coll.name}] progress: {done}/{todo}")
    remaining = coll.count_documents(_FILTER)
    print(f"[{coll.name}] stamped {done}; remaining (expect 0): {remaining}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show per-collection counts and a sample parse without writing.",
    )
    args = parser.parse_args()

    mongodb_uri = os.environ.get("MONGODB_URI")
    if not mongodb_uri:
        sys.exit("MONGODB_URI not set in environment.")
    db_name = os.environ.get("DB_NAME", "url-shortener")

    client: MongoClient = MongoClient(mongodb_uri)
    db = client[db_name]
    for name, field in _COLLECTIONS:
        backfill(db[name], field, args.dry_run)
    client.close()


if __name__ == "__main__":
    main()
