"""Tests for GET /api/v1/domain-intel (host records endpoint)."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient

from dependencies import get_current_user
from infrastructure.cache.meta_fetch_cache import MetaFetchCache
from services.domain_intel_service import DomainIntelService

from .conftest import _build_test_app

INTEL = {
    "host": "dest.example",
    "registrable_domain": "dest.example",
    "dns": {"a": ["93.184.216.34"], "aaaa": [], "mx": [], "ns": [], "txt": []},
    "whois": {
        "registrar": "Example Registrar",
        "created": "2020-01-01T00:00:00Z",
        "updated": None,
        "expires": "2030-01-01T00:00:00Z",
        "age_days": 2432,
    },
    "ssl": {
        "issuer": "Example CA",
        "subject": "dest.example",
        "valid_from": "Jan  1 00:00:00 2026 GMT",
        "valid_to": "Jan  1 00:00:00 2027 GMT",
        "days_left": 125,
        "sans": ["dest.example"],
    },
    "fetched_at": "2026-08-29T00:00:00+00:00",
}


def _app():
    app = _build_test_app({get_current_user: lambda: None})
    app.state.domain_intel_service = DomainIntelService(MetaFetchCache(None))
    return app


def test_domain_intel_returns_records_anonymously():
    with (
        patch.object(DomainIntelService, "lookup", new=AsyncMock(return_value=INTEL)),
        TestClient(_app(), raise_server_exceptions=True) as client,
    ):
        resp = client.get("/api/v1/domain-intel", params={"host": "dest.example"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["dns"]["a"] == ["93.184.216.34"]
    assert data["whois"]["age_days"] == 2432
    assert data["ssl"]["issuer"] == "Example CA"


def test_domain_intel_rejects_garbage_host():
    with TestClient(_app(), raise_server_exceptions=False) as client:
        resp = client.get("/api/v1/domain-intel", params={"host": "not a host!"})
    assert resp.status_code == 400
