"""GET /api/v1/me/features — per-account feature availability."""

from __future__ import annotations

from unittest.mock import AsyncMock

from fastapi.testclient import TestClient

from dependencies import get_current_user, get_feature_flag_service, require_jwt
from services.feature_flag_service import (
    AB_TESTING_FLAG,
    CUSTOM_DOMAINS_FLAG,
    EXPOSED_FEATURES,
    GEO_TARGETING_FLAG,
    META_TAGS_FLAG,
    FeatureFlagService,
)

from .conftest import _build_test_app, _make_user


def _flag_svc(enabled_names: set[str]) -> FeatureFlagService:
    """A real service instance with only ``is_enabled`` faked, so the test
    exercises the real ``states_for`` policy (enabled vs hidden)."""
    svc = FeatureFlagService.__new__(FeatureFlagService)

    async def _is_enabled(name: str, user) -> bool:
        return name in enabled_names

    svc.is_enabled = _is_enabled  # type: ignore[method-assign]
    return svc


def _app(user, enabled_names: set[str]):
    return _build_test_app(
        {
            require_jwt: lambda: user,
            get_current_user: lambda: user,
            get_feature_flag_service: lambda: _flag_svc(enabled_names),
        }
    )


def test_requires_auth():
    # No auth override at all: the real require_jwt runs and rejects.
    app = _build_test_app({get_feature_flag_service: lambda: AsyncMock()})
    with TestClient(app, raise_server_exceptions=False) as client:
        resp = client.get("/api/v1/me/features")
    assert resp.status_code == 401


def test_all_hidden_by_default():
    # No flags registered → default-deny → every exposed feature is hidden.
    user = _make_user()
    with TestClient(_app(user, set())) as client:
        resp = client.get("/api/v1/me/features")
    assert resp.status_code == 200
    features = resp.json()["features"]
    assert set(features) == set(EXPOSED_FEATURES)
    assert set(features.values()) == {"hidden"}


def test_enabled_flags_surface_as_enabled():
    user = _make_user()
    enabled = {GEO_TARGETING_FLAG, CUSTOM_DOMAINS_FLAG}
    with TestClient(_app(user, enabled)) as client:
        resp = client.get("/api/v1/me/features")
    features = resp.json()["features"]
    assert features[GEO_TARGETING_FLAG] == "enabled"
    assert features[CUSTOM_DOMAINS_FLAG] == "enabled"
    assert features[META_TAGS_FLAG] == "hidden"
    assert features[AB_TESTING_FLAG] == "hidden"


def test_response_covers_every_exposed_feature():
    # The contract clients rely on: the map always carries the full registry,
    # so a frontend can treat "missing" as hidden without ever hitting it.
    user = _make_user()
    with TestClient(_app(user, set(EXPOSED_FEATURES))) as client:
        resp = client.get("/api/v1/me/features")
    features = resp.json()["features"]
    assert set(features) == set(EXPOSED_FEATURES)
    assert set(features.values()) == {"enabled"}
