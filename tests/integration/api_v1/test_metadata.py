"""Tests for GET /api/v1/metadata (destination tag parser endpoint)."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient

from dependencies import get_current_user
from infrastructure.cache.meta_fetch_cache import MetaFetchCache
from infrastructure.safe_fetch import FetchedBody, FetchHardError, FetchTransientError

from .conftest import _build_test_app, _make_user

HTML = b"""<html><head>
<meta property="og:title" content="Dest Title">
<meta property="og:image" content="/og.png">
</head><body></body></html>"""


def _app(user=None):
    app = _build_test_app({get_current_user: lambda: user or _make_user()})
    app.state.meta_fetch_cache = MetaFetchCache(None)  # no-op cache
    return app


def test_metadata_requires_auth():
    app = _build_test_app({get_current_user: lambda: None})
    app.state.meta_fetch_cache = MetaFetchCache(None)
    with TestClient(app, raise_server_exceptions=False) as client:
        resp = client.get("/api/v1/metadata", params={"url": "https://dest.example"})
    assert resp.status_code == 401


def test_metadata_parses_destination():
    body = FetchedBody(HTML, "text/html", "https://dest.example/final")
    with patch(
        "routes.api_v1.metadata.fetch_public", new=AsyncMock(return_value=body)
    ):
        with TestClient(_app(), raise_server_exceptions=True) as client:
            resp = client.get(
                "/api/v1/metadata", params={"url": "https://dest.example/a"}
            )
    assert resp.status_code == 200
    data = resp.json()
    assert data["title"] == "Dest Title"
    assert data["image"] == "https://dest.example/og.png"  # resolved vs final_url
    assert data["final_url"] == "https://dest.example/final"
    assert data["og"]["title"] == "Dest Title"


def test_metadata_rejects_http_url():
    with TestClient(_app(), raise_server_exceptions=False) as client:
        resp = client.get("/api/v1/metadata", params={"url": "http://dest.example"})
    assert resp.status_code == 400


def test_metadata_unfetchable_is_422():
    with patch(
        "routes.api_v1.metadata.fetch_public",
        new=AsyncMock(side_effect=FetchHardError("resolves to a non-public address")),
    ):
        with TestClient(_app(), raise_server_exceptions=False) as client:
            resp = client.get(
                "/api/v1/metadata", params={"url": "https://internal.example"}
            )
    assert resp.status_code == 422
    assert resp.json()["code"] == "unfetchable"


def test_metadata_timeout_is_504():
    with patch(
        "routes.api_v1.metadata.fetch_public",
        new=AsyncMock(side_effect=FetchTransientError("timeout")),
    ):
        with TestClient(_app(), raise_server_exceptions=False) as client:
            resp = client.get(
                "/api/v1/metadata", params={"url": "https://slow.example"}
            )
    assert resp.status_code == 504
