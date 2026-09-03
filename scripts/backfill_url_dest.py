#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "idna>=3.6",
#     "pymongo>=4.6",
#     "tldextract>=5.1",
# ]
# ///
"""Migration: stamp parsed `dest` parts on every url doc missing them.

Covers urlsV2 (long_url), urls (url) and emojis (url). Standalone: no spoo
project context required. Parse logic mirrors
``shared/url_utils.parse_destination``; keep the two in sync.

Unparseable destinations are stamped ``dest: null`` so the needs-backfill
filter converges to zero; null adds nothing to the sparse dest_registrable
index.

Second pass, urlsV2 only: links with geo_rules or a pre_start_url get
``dest.secondary_hosts`` (every extra destination host but the main one) and
the index-aligned ``dest.secondary_registrable``, so a host block and a
feed-domain sweep both reach links that hide the host in a rule. Idempotent:
docs already carrying the fields are skipped, and a link whose extra
destinations add no new host gets empty lists so the filter converges.

Run it from the project environment: ``uv run python scripts/backfill_url_dest.py``.
The inline script header below also works, but only with PyPI reachable.

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

import idna
import tldextract
from pymongo import MongoClient, UpdateOne
from pymongo.errors import BulkWriteError

_FILTER = {"dest": {"$exists": False}}
_SECONDARY_FILTER = {
    "$and": [
        {
            "$or": [
                {"geo_rules": {"$type": "object"}},
                {"pre_start_url": {"$type": "string"}},
            ]
        },
        {
            "$or": [
                {
                    "dest": {"$type": "object"},
                    "dest.secondary_registrable": {"$exists": False},
                },
                # An unparseable long_url left dest null; its geo hosts still count.
                {"dest": None},
            ]
        },
    ]
}
_EMPTY_DEST = {"scheme": "", "host": "", "subdomain": "", "registrable_domain": ""}
_BATCH = 1_000
_COLLECTIONS = (("urlsV2", "long_url"), ("urls", "url"), ("emojis", "url"))
_tld = tldextract.TLDExtract(cache_dir=None, suffix_list_urls=())


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
        with contextlib.suppress(idna.IDNAError):
            host = idna.encode(host, uts46=True).decode("ascii")
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


def secondary_urls(doc: dict) -> list:
    """Every extra destination a link routes to: geo rules and the pre-start page."""
    geo = doc.get("geo_rules")
    urls = list(geo.values()) if isinstance(geo, dict) else []
    if isinstance(doc.get("pre_start_url"), str):
        urls.append(doc["pre_start_url"])
    return urls


def secondary_parts(urls: list, main_host: str) -> list[dict]:
    """Mirror of shared/url_utils._secondary_parts: one parsed destination per
    distinct host, sorted by host."""
    by_host: dict[str, dict] = {}
    for parts in (parse_destination(u) for u in urls):
        if parts is not None and parts["host"] != main_host:
            by_host.setdefault(parts["host"], parts)
    return [by_host[h] for h in sorted(by_host)]


def secondary_hosts(urls: list, main_host: str) -> list[str]:
    return [p["host"] for p in secondary_parts(urls, main_host)]


def secondary_fields(urls: list, main_host: str) -> dict:
    """Both secondary lists, index-aligned, empty when nothing adds a host."""
    parts = secondary_parts(urls, main_host)
    return {
        "secondary_hosts": [p["host"] for p in parts],
        "secondary_registrable": [p["registrable_domain"] for p in parts],
    }


def dest_for(doc: dict, url_field: str) -> dict | None:
    """The full dest stamp for one doc: parsed parts plus secondary lists."""
    parts = parse_destination(doc.get(url_field))
    extra = secondary_fields(secondary_urls(doc), (parts or {}).get("host", ""))
    if parts is None and not extra["secondary_hosts"]:
        return None
    stamp = dict(
        parts or {"scheme": "", "host": "", "subdomain": "", "registrable_domain": ""}
    )
    if extra["secondary_hosts"]:
        stamp.update(extra)
    return stamp


def _secondary_set(d: dict) -> dict:
    """What the second pass writes: both lists on an existing stamp, or a
    whole stamp when dest is null. Empty lists are the convergence marker."""
    if isinstance(d.get("dest"), dict):
        fields = secondary_fields(secondary_urls(d), d["dest"].get("host", ""))
        return {f"dest.{k}": v for k, v in fields.items()}
    stamp = dest_for(d, "long_url") or dict(_EMPTY_DEST)
    stamp.setdefault("secondary_hosts", [])
    stamp.setdefault("secondary_registrable", [])
    return {"dest": stamp}


def _secondary_op(d: dict) -> UpdateOne:
    # The filter re-asserts what was read, so a doc edited in between is
    # left for the next run instead of overwritten with stale hosts.
    flt = {
        "_id": d["_id"],
        "geo_rules": d.get("geo_rules"),
        "pre_start_url": d.get("pre_start_url"),
        "dest.secondary_registrable": {"$exists": False},
    }
    if isinstance(d.get("dest"), dict):
        flt["dest.host"] = d["dest"].get("host", "")
    else:
        flt["dest"] = None
    return UpdateOne(flt, {"$set": _secondary_set(d)})


def backfill_secondary(coll, dry_run: bool) -> None:
    todo = coll.count_documents(_SECONDARY_FILTER)
    print(f"[{coll.name}] geo or scheduled links needing secondary fields: {todo}")
    if todo == 0 or dry_run:
        return
    stamped = failed = skipped = 0
    last_id = None
    while True:
        query = dict(_SECONDARY_FILTER)
        if last_id is not None:
            query["_id"] = {"$gt": last_id}
        batch = list(
            coll.find(
                query,
                {"dest": 1, "long_url": 1, "geo_rules": 1, "pre_start_url": 1},
            )
            .sort("_id", 1)
            .limit(_BATCH)
        )
        if not batch:
            break
        last_id = batch[-1]["_id"]
        ops = [_secondary_op(d) for d in batch]
        try:
            skipped += len(ops) - coll.bulk_write(ops, ordered=False).matched_count
        except BulkWriteError as exc:
            errors = exc.details.get("writeErrors", [])
            failed += len(errors)
            skipped += max(0, len(ops) - exc.details.get("nMatched", 0) - len(errors))
        stamped += len(batch)
    remaining = coll.count_documents(_SECONDARY_FILTER)
    print(
        f"[{coll.name}] secondary fields stamped {stamped - failed - skipped}; "
        f"failed: {failed}; skipped (changed meanwhile): {skipped}; "
        f"remaining (expect {failed + skipped}): {remaining}"
    )


def backfill(coll, url_field: str, dry_run: bool) -> None:
    todo = coll.count_documents(_FILTER)
    print(f"[{coll.name}] docs needing backfill: {todo}")
    if todo == 0:
        return
    if dry_run:
        sample = coll.find_one(
            _FILTER, {url_field: 1, "geo_rules": 1, "pre_start_url": 1}
        )
        print(f"[{coll.name}] sample parse: {dest_for(sample or {}, url_field)}")
        return
    done = 0
    failed = 0
    skipped = 0
    last_id = None
    # Ride _id: the filter has no usable index, and this also carries the scan
    # past any doc whose update fails instead of dying on it forever.
    while True:
        query = dict(_FILTER)
        if last_id is not None:
            query["_id"] = {"$gt": last_id}
        batch = list(
            coll.find(query, {url_field: 1, "geo_rules": 1, "pre_start_url": 1})
            .sort("_id", 1)
            .limit(_BATCH)
        )
        if not batch:
            break
        last_id = batch[-1]["_id"]
        # The filter re-asserts what was read: a doc edited between the read
        # and this write is left for the next run instead of overwritten.
        ops = [
            UpdateOne(
                {
                    "_id": d["_id"],
                    url_field: d.get(url_field),
                    "geo_rules": d.get("geo_rules"),
                    "dest": {"$exists": False},
                },
                {"$set": {"dest": dest_for(d, url_field)}},
            )
            for d in batch
        ]
        try:
            skipped += len(ops) - coll.bulk_write(ops, ordered=False).matched_count
        except BulkWriteError as exc:
            # v1 docs at the 16MB ceiling reject any $set: one skipped row,
            # never the migration.
            errors = exc.details.get("writeErrors", [])
            failed += len(errors)
            skipped += max(0, len(ops) - exc.details.get("nMatched", 0) - len(errors))
            for err in errors[:10]:
                print(
                    f"[{coll.name}] SKIPPED _id={err.get('op', {}).get('q')}: "
                    f"code={err.get('code')} {err.get('errmsg', '')[:120]}"
                )
        done += len(batch)
        if done % 50_000 < _BATCH:
            print(f"[{coll.name}] progress: {done}/{todo}")
    remaining = coll.count_documents(_FILTER)
    print(
        f"[{coll.name}] stamped {done - failed - skipped}; failed: {failed}; "
        f"skipped (changed meanwhile): {skipped}; "
        f"remaining (expect {failed + skipped}): {remaining}"
    )


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
    backfill_secondary(db["urlsV2"], args.dry_run)
    client.close()


if __name__ == "__main__":
    main()
