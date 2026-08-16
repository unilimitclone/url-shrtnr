"""Tests for GET /api/v1/stats and GET /api/v1/stats/links/{url_id}."""

from __future__ import annotations

from typing import ClassVar
from unittest.mock import AsyncMock

from bson import ObjectId
from fastapi.testclient import TestClient

from dependencies import get_current_user, get_stats_service, get_url_service
from errors import NotFoundError

from .conftest import _build_test_app, _make_api_key_doc, _make_url_doc, _make_user

_SUMMARY = {
    "total_clicks": 42,
    "unique_clicks": 20,
    "first_click": "2024-01-01T00:00:00+00:00",
    "last_click": "2024-01-07T00:00:00+00:00",
    "avg_redirection_time": 1.5,
}
_TIME_BUCKET_INFO = {
    "strategy": "daily",
    "mongo_format": "%Y-%m-%d",
    "display_format": "%Y-%m-%d",
    "timezone": "UTC",
}
_BASE_STATS_RESULT = {
    "timezone": "UTC",
    "group_by": ["time"],
    "filters": {},
    "time_range": {
        "start_date": "2024-01-01T00:00:00+00:00",
        "end_date": "2024-01-08T00:00:00+00:00",
    },
    "summary": _SUMMARY,
    "metrics": {},
    "generated_at": "2024-01-08T00:00:00+00:00",
    "api_version": "v1",
}


class TestStats:
    _STATS_RESULT: ClassVar[dict] = {
        **_BASE_STATS_RESULT,
        "scope": "anon",
        "short_code": "abc123",
        "time_bucket_info": _TIME_BUCKET_INFO,
    }

    def test_stats_anon_scope(self):
        mock_svc = AsyncMock()
        mock_svc.query = AsyncMock(return_value=self._STATS_RESULT)

        application = _build_test_app(
            {get_current_user: lambda: None, get_stats_service: lambda: mock_svc}
        )
        with TestClient(application, raise_server_exceptions=True) as client:
            resp = client.get("/api/v1/stats?scope=anon&short_code=abc123")

        assert resp.status_code == 200
        body = resp.json()
        assert body["scope"] == "anon"
        assert body["summary"]["total_clicks"] == 42
        assert "time_bucket_info" in body
        assert body["time_bucket_info"]["strategy"] == "daily"

    def test_stats_all_scope_with_auth(self):
        user = _make_user()
        mock_svc = AsyncMock()
        mock_svc.query = AsyncMock(return_value={**_BASE_STATS_RESULT, "scope": "all"})

        application = _build_test_app(
            {get_current_user: lambda: user, get_stats_service: lambda: mock_svc}
        )
        with TestClient(application, raise_server_exceptions=True) as client:
            resp = client.get("/api/v1/stats?scope=all")

        assert resp.status_code == 200

    def test_stats_invalid_scope_returns_422(self):
        application = _build_test_app(
            {get_current_user: lambda: None, get_stats_service: lambda: AsyncMock()}
        )
        with TestClient(application, raise_server_exceptions=False) as client:
            resp = client.get("/api/v1/stats?scope=invalid_value")

        assert resp.status_code == 422

    def test_stats_api_key_missing_scope_returns_403(self):
        key_doc = _make_api_key_doc(scopes=["shorten:create"])
        user = _make_user(api_key_doc=key_doc)

        application = _build_test_app(
            {get_current_user: lambda: user, get_stats_service: lambda: AsyncMock()}
        )
        with TestClient(application, raise_server_exceptions=False) as client:
            resp = client.get("/api/v1/stats?scope=anon&short_code=abc123")

        assert resp.status_code == 403

    def test_stats_url_id_filter_reaches_service(self):
        user = _make_user()
        oid = str(ObjectId())
        mock_svc = AsyncMock()
        mock_svc.query = AsyncMock(return_value={**_BASE_STATS_RESULT, "scope": "all"})

        application = _build_test_app(
            {get_current_user: lambda: user, get_stats_service: lambda: mock_svc}
        )
        with TestClient(application, raise_server_exceptions=True) as client:
            resp = client.get(f"/api/v1/stats?url_id={oid}")

        assert resp.status_code == 200
        query = mock_svc.query.call_args[0][0]
        assert query.parsed_filters["url_id"] == [oid]

    def test_stats_invalid_url_id_filter_returns_422(self):
        user = _make_user()
        application = _build_test_app(
            {get_current_user: lambda: user, get_stats_service: lambda: AsyncMock()}
        )
        with TestClient(application, raise_server_exceptions=False) as client:
            resp = client.get("/api/v1/stats?url_id=not-an-objectid")

        assert resp.status_code == 422


class TestLinkStats:
    _URL_ID: ClassVar[str] = str(ObjectId("e" * 24))
    _LINK_STATS_RESULT: ClassVar[dict] = {
        **_BASE_STATS_RESULT,
        "scope": "all",
        "url_id": _URL_ID,
        "alias": "mylink",
        "time_bucket_info": _TIME_BUCKET_INFO,
    }

    def _app(self, *, user=None, stats_svc=None, url_svc=None):
        return _build_test_app(
            {
                get_current_user: lambda: user,
                get_stats_service: lambda: stats_svc or AsyncMock(),
                get_url_service: lambda: url_svc or AsyncMock(),
            }
        )

    def test_link_stats_happy_path(self):
        user = _make_user()
        url_doc = _make_url_doc(alias="mylink", owner_id=user.user_id)
        url_svc = AsyncMock()
        url_svc.get_owned = AsyncMock(return_value=url_doc)
        stats_svc = AsyncMock()
        stats_svc.query_link = AsyncMock(return_value=self._LINK_STATS_RESULT)

        application = self._app(user=user, stats_svc=stats_svc, url_svc=url_svc)
        with TestClient(application, raise_server_exceptions=True) as client:
            resp = client.get(f"/api/v1/stats/links/{self._URL_ID}")

        assert resp.status_code == 200
        body = resp.json()
        assert body["url_id"] == self._URL_ID
        assert body["alias"] == "mylink"
        assert body["scope"] == "all"
        # Resolve-first: get_owned runs before the query.
        url_svc.get_owned.assert_awaited_once_with(ObjectId(self._URL_ID), user.user_id)
        stats_svc.query_link.assert_awaited_once()

    def test_link_stats_foreign_id_answers_like_missing(self):
        """No existence oracle: get_owned 404s identically for foreign and
        missing ids — and the stats query never runs."""
        user = _make_user()
        url_svc = AsyncMock()
        url_svc.get_owned = AsyncMock(side_effect=NotFoundError("URL not found"))
        stats_svc = AsyncMock()

        application = self._app(user=user, stats_svc=stats_svc, url_svc=url_svc)
        with TestClient(application, raise_server_exceptions=False) as client:
            resp = client.get(f"/api/v1/stats/links/{self._URL_ID}")

        assert resp.status_code == 404
        stats_svc.query_link.assert_not_awaited()

    def test_link_stats_invalid_object_id_returns_400(self):
        user = _make_user()
        application = self._app(user=user)
        with TestClient(application, raise_server_exceptions=False) as client:
            resp = client.get("/api/v1/stats/links/not-an-objectid")

        assert resp.status_code == 400

    def test_link_stats_unauthenticated_returns_401(self):
        application = self._app(user=None)
        with TestClient(application, raise_server_exceptions=False) as client:
            resp = client.get(f"/api/v1/stats/links/{self._URL_ID}")

        assert resp.status_code == 401

    def test_link_stats_api_key_missing_scope_returns_403(self):
        key_doc = _make_api_key_doc(scopes=["shorten:create"])
        user = _make_user(api_key_doc=key_doc)

        application = self._app(user=user)
        with TestClient(application, raise_server_exceptions=False) as client:
            resp = client.get(f"/api/v1/stats/links/{self._URL_ID}")

        assert resp.status_code == 403

    def test_link_stats_utm_group_by_accepted(self):
        user = _make_user()
        url_doc = _make_url_doc(alias="mylink", owner_id=user.user_id)
        url_svc = AsyncMock()
        url_svc.get_owned = AsyncMock(return_value=url_doc)
        stats_svc = AsyncMock()
        stats_svc.query_link = AsyncMock(
            return_value={**self._LINK_STATS_RESULT, "group_by": ["utm_source"]}
        )

        application = self._app(user=user, stats_svc=stats_svc, url_svc=url_svc)
        with TestClient(application, raise_server_exceptions=True) as client:
            resp = client.get(f"/api/v1/stats/links/{self._URL_ID}?group_by=utm_source")

        assert resp.status_code == 200

    def test_link_stats_short_code_group_by_rejected(self):
        user = _make_user()
        application = self._app(user=user)
        with TestClient(application, raise_server_exceptions=False) as client:
            resp = client.get(f"/api/v1/stats/links/{self._URL_ID}?group_by=short_code")

        assert resp.status_code == 422
