"""The backfill stamps secondary hosts on existing geo links, once."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from unittest.mock import MagicMock

_SPEC = importlib.util.spec_from_file_location(
    "backfill_url_dest", Path(__file__).parents[3] / "scripts" / "backfill_url_dest.py"
)
backfill = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(backfill)


def test_secondary_hosts_mirror_the_shared_helper():
    from shared.url_utils import secondary_hosts

    rules = {
        "IN": "https://B.example/x",
        "US": "https://a.example/",
        "DE": "https://main.example/",
    }
    urls = backfill.secondary_urls(
        {"geo_rules": rules, "pre_start_url": "https://teaser.example/"}
    )
    assert backfill.secondary_hosts(urls, "main.example") == [
        "a.example",
        "b.example",
        "teaser.example",
    ]
    assert backfill.secondary_hosts(urls, "main.example") == secondary_hosts(
        urls, exclude="main.example"
    )
    assert backfill.secondary_urls({"geo_rules": None, "pre_start_url": None}) == []


def test_dest_for_includes_secondary_hosts_only_when_present():
    plain = backfill.dest_for({"long_url": "https://main.example/p"}, "long_url")
    assert plain["host"] == "main.example" and "secondary_hosts" not in plain
    geo = backfill.dest_for(
        {
            "long_url": "https://main.example/p",
            "geo_rules": {"IN": "https://geo.example/"},
        },
        "long_url",
    )
    assert geo["secondary_hosts"] == ["geo.example"]
    assert backfill.dest_for({"long_url": "nonsense"}, "long_url") is None
    scheduled = backfill.dest_for(
        {
            "long_url": "https://main.example/",
            "pre_start_url": "https://teaser.example/",
        },
        "long_url",
    )
    assert scheduled["secondary_hosts"] == ["teaser.example"]


def test_backfill_secondary_stamps_and_reports(capsys):
    docs = [
        {
            "_id": 1,
            "dest": {"host": "main.example"},
            "geo_rules": {"IN": "https://geo.example/"},
        },
        {
            "_id": 2,
            "dest": {"host": "main.example"},
            "geo_rules": {"IN": "https://main.example/in"},
        },
    ]
    col = MagicMock()
    col.name = "urlsV2"
    col.count_documents = MagicMock(side_effect=[2, 0])
    cursor = MagicMock()
    cursor.sort.return_value.limit = MagicMock(side_effect=[docs, []])
    col.find = MagicMock(return_value=cursor)

    backfill.backfill_secondary(col, dry_run=False)

    ops = col.bulk_write.call_args.args[0]
    sets = {op._filter["_id"]: op._doc["$set"]["dest.secondary_hosts"] for op in ops}
    # A rule that adds no new host still gets [] so the filter converges.
    assert sets == {1: ["geo.example"], 2: []}
    out = capsys.readouterr().out
    assert "geo or scheduled links needing secondary_hosts: 2" in out
    assert "secondary_hosts stamped 2; failed: 0; remaining (expect 0): 0" in out


def test_backfill_secondary_dry_run_writes_nothing(capsys):
    col = MagicMock()
    col.name = "urlsV2"
    col.count_documents = MagicMock(return_value=5)
    backfill.backfill_secondary(col, dry_run=True)
    col.bulk_write.assert_not_called()
    assert "needing secondary_hosts: 5" in capsys.readouterr().out


def test_secondary_pass_repairs_a_null_dest_with_valid_geo_hosts():
    stamp = backfill._secondary_set(
        {
            "_id": 9,
            "dest": None,
            "long_url": "nonsense",
            "geo_rules": {"IN": "https://geo.example/"},
        }
    )
    assert stamp == {
        "dest": {
            "scheme": "",
            "host": "",
            "subdomain": "",
            "registrable_domain": "",
            "secondary_hosts": ["geo.example"],
        }
    }
    # Nothing parseable at all still converges instead of matching forever.
    nothing = backfill._secondary_set(
        {
            "_id": 10,
            "dest": None,
            "long_url": "nonsense",
            "geo_rules": {"IN": "also nonsense"},
        }
    )
    assert nothing["dest"]["secondary_hosts"] == []
    assert backfill._SECONDARY_FILTER["$and"][1]["$or"][1] == {"dest": None}
