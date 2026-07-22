"""Unit tests for request logging middleware helpers (_client_tag, _auth_kind)."""

from __future__ import annotations

import pytest
from starlette.requests import Request

from middleware.logging import _auth_kind, _client_tag


def _request(headers: dict[str, str] | None = None) -> Request:
    raw_headers = [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()]
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "headers": raw_headers,
        "query_string": b"",
    }
    return Request(scope)


# ── _client_tag ──────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("dashboard", ("dashboard", None)),
        ("landing", ("landing", None)),
        ("snap/2.1.0", ("snap", "2.1.0")),
        ("cli/0.3.0-beta.1", ("cli", "0.3.0-beta.1")),
        ("bot", ("bot", None)),
    ],
)
def test_client_tag_valid(value: str, expected: tuple):
    assert _client_tag(_request({"X-Spoo-Client": value})) == expected


@pytest.mark.parametrize(
    "value",
    [
        "",
        "Dashboard",  # uppercase slug
        "a" * 33,  # slug too long
        "snap/" + "1" * 17,  # version too long
        "snap/2.1.0/extra",
        "sn ap",
        "snap;DROP",
    ],
)
def test_client_tag_invalid_treated_as_absent(value: str):
    assert _client_tag(_request({"X-Spoo-Client": value})) == (None, None)


def test_client_tag_missing_header():
    assert _client_tag(_request()) == (None, None)


def test_client_tag_strips_whitespace():
    assert _client_tag(_request({"X-Spoo-Client": " raycast "})) == (
        "raycast",
        None,
    )


# ── _auth_kind ───────────────────────────────────────────────────────────────


def test_auth_kind_api_key():
    req = _request({"Authorization": "Bearer spoo_abc123"})
    assert _auth_kind(req) == "api_key"


def test_auth_kind_jwt_bearer():
    req = _request({"Authorization": "Bearer aaa.bbb.ccc"})
    assert _auth_kind(req) == "jwt"


def test_auth_kind_bearer_other():
    req = _request({"Authorization": "Bearer something-else"})
    assert _auth_kind(req) == "bearer_other"


def test_auth_kind_access_token_cookie():
    req = _request({"Cookie": "access_token=aaa.bbb.ccc"})
    assert _auth_kind(req) == "jwt_cookie"


def test_auth_kind_legacy_session_cookie():
    req = _request({"Cookie": "session=xyz"})
    assert _auth_kind(req) == "session_cookie"


def test_auth_kind_access_token_beats_session_cookie():
    req = _request({"Cookie": "session=xyz; access_token=aaa.bbb.ccc"})
    assert _auth_kind(req) == "jwt_cookie"


def test_auth_kind_bearer_beats_cookie():
    req = _request(
        {"Authorization": "Bearer spoo_abc", "Cookie": "access_token=aaa.bbb.ccc"}
    )
    assert _auth_kind(req) == "api_key"


def test_auth_kind_anonymous():
    assert _auth_kind(_request()) == "anonymous"
