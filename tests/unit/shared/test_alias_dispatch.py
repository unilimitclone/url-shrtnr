"""Unit tests for shared/alias_dispatch.py — the resolution-order table.

This order is a public contract shared by the redirect and the public
preview endpoint; the table below is the single place it is spelled out.
"""

from __future__ import annotations

import pytest

from schemas.models.url import SchemaVersion
from shared.alias_dispatch import resolution_order


@pytest.mark.parametrize(
    ("short_code", "expected"),
    [
        # emoji aliases → emojis collection only
        ("🚀", (SchemaVersion.EMOJI,)),
        ("🚀✨", (SchemaVersion.EMOJI,)),
        # percent-encoded emoji still detected (is_emoji_alias unquotes)
        ("%F0%9F%9A%80", (SchemaVersion.EMOJI,)),
        # 6 chars → v1 first (v1 codes were generated at this length)
        ("abc123", (SchemaVersion.V1, SchemaVersion.V2)),
        ("Docs12", (SchemaVersion.V1, SchemaVersion.V2)),
        # 7 chars → v2 first (historically an explicit branch, same order
        # as the default)
        ("abcd123", (SchemaVersion.V2, SchemaVersion.V1)),
        # anything else → v2 first
        ("ab", (SchemaVersion.V2, SchemaVersion.V1)),
        ("short", (SchemaVersion.V2, SchemaVersion.V1)),
        ("a-much-longer-alias", (SchemaVersion.V2, SchemaVersion.V1)),
        ("", (SchemaVersion.V2, SchemaVersion.V1)),
    ],
)
def test_resolution_order_table(short_code, expected):
    assert resolution_order(short_code) == expected
