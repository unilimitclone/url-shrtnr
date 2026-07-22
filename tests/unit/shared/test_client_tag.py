"""Unit tests for shared/client_tag.py — X-Spoo-Client parsing."""

from __future__ import annotations

import pytest

from shared.client_tag import parse_client_tag


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("dashboard", ("dashboard", None)),
        ("snap/2.1.0", ("snap", "2.1.0")),
        ("cli/0.3.0-beta.1", ("cli", "0.3.0-beta.1")),
        (" raycast ", ("raycast", None)),
    ],
)
def test_parse_valid(value, expected):
    assert parse_client_tag(value) == expected


@pytest.mark.parametrize(
    "value",
    [
        None,
        "",
        "Dashboard",
        "a" * 33,
        "snap/" + "1" * 17,
        "snap/2.1.0/extra",
        "sn ap",
        "snap;DROP",
    ],
)
def test_parse_invalid_is_absent(value):
    assert parse_client_tag(value) == (None, None)
