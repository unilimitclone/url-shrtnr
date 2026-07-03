"""
Integration tests for the redirect and legacy URL shortener routes.

Uses the _build_test_app pattern from test_api_v1.py — no real infrastructure needed.
The redirect route emits ClickEvents through a ClickEventSink; these tests override
``get_click_sink`` and assert on the emitted event.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

from fastapi.testclient import TestClient

from dependencies import get_click_sink, get_url_service
from errors import (
    BlockedUrlError,
    ForbiddenError,
    GoneError,
    NotFoundError,
    ValidationError,
)
from infrastructure.cache.url_cache import UrlCacheData
from routes.redirect_routes import router as redirect_router
from services.click.events import ClickEvent
from tests.conftest import build_test_app
from tests.factories import make_url_cache


def _make_url_cache(schema: str = "v2", **overrides) -> UrlCacheData:
    # Shape lives in tests/factories.py; this file's tests spell the
    # schema kwarg without the _version suffix.
    return make_url_cache(schema_version=schema, domain="", **overrides)


BOT_UA = "Googlebot/2.1 (+http://www.google.com/bot.html)"
BROWSER_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0 Safari/537.36"
)


# ── Mock services ─────────────────────────────────────────────────────────────


def _mock_url_service(url_data: UrlCacheData, schema: str = "v2"):
    svc = MagicMock()
    svc.resolve = AsyncMock(return_value=(url_data, schema))
    return svc


def _mock_click_sink():
    sink = MagicMock()
    sink.emit = AsyncMock(return_value=None)
    return sink


def _build_app(url_svc, click_sink=None):
    return build_test_app(
        redirect_router,
        overrides={
            get_url_service: lambda: url_svc,
            get_click_sink: lambda: click_sink or _mock_click_sink(),
        },
    )


# ── Redirect tests ────────────────────────────────────────────────────────────


def test_redirect_v2_url():
    url_data = _make_url_cache(long_url="https://example.com/target")
    app = _build_app(_mock_url_service(url_data))
    with TestClient(app, follow_redirects=False) as client:
        resp = client.get("/abc1234")
    assert resp.status_code == 302
    assert resp.headers["location"] == "https://example.com/target"
    assert resp.headers.get("x-robots-tag") == "noindex, nofollow, noarchive"


def test_redirect_emits_click_event_snapshot():
    """The emitted event snapshots the resolved URL so consumers never re-resolve."""
    url_data = _make_url_cache(long_url="https://example.com/target")
    sink = _mock_click_sink()
    app = _build_app(_mock_url_service(url_data), sink)
    with TestClient(app, follow_redirects=False) as client:
        resp = client.get(
            "/abc1234",
            headers={"User-Agent": BROWSER_UA, "Referer": "https://t.co/x"},
        )
    assert resp.status_code == 302
    sink.emit.assert_awaited_once()
    event = sink.emit.await_args.args[0]
    assert isinstance(event, ClickEvent)
    assert event.short_code == "abc1234"
    assert event.schema_key == "v2"
    assert event.is_emoji is False
    assert event.url.long_url == "https://example.com/target"
    assert event.user_agent == BROWSER_UA
    assert event.referrer == "https://t.co/x"
    assert event.redirect_ms >= 0


def test_redirect_event_strips_password_hash():
    """v1 password hashes are plaintext — they must never enter the event."""
    url_data = _make_url_cache(password_hash="mypassword", schema="v1")
    sink = _mock_click_sink()
    app = _build_app(_mock_url_service(url_data, schema="v1"), sink)
    with TestClient(app, follow_redirects=False) as client:
        resp = client.get("/abc1234?password=mypassword")
    assert resp.status_code == 302
    event = sink.emit.await_args.args[0]
    assert event.url.password_hash is None


def test_redirect_not_found_returns_404_html():
    url_svc = MagicMock()
    url_svc.resolve = AsyncMock(side_effect=NotFoundError("not found"))
    app = _build_app(url_svc)
    with TestClient(app) as client:
        resp = client.get("/notexist")
    assert resp.status_code == 404
    assert "text/html" in resp.headers["content-type"]


def test_redirect_blocked_url_returns_451_html():
    url_svc = MagicMock()
    url_svc.resolve = AsyncMock(side_effect=BlockedUrlError("blocked"))
    app = _build_app(url_svc)
    with TestClient(app) as client:
        resp = client.get("/blocked1")
    assert resp.status_code == 451
    assert "text/html" in resp.headers["content-type"]


def test_redirect_expired_url_returns_410_html():
    url_svc = MagicMock()
    url_svc.resolve = AsyncMock(side_effect=GoneError("expired"))
    app = _build_app(url_svc)
    with TestClient(app) as client:
        resp = client.get("/expired1")
    assert resp.status_code == 410
    assert "text/html" in resp.headers["content-type"]


def test_redirect_password_protected_no_password_returns_401_html():
    url_data = _make_url_cache(password_hash="$2b$12$hashed")
    app = _build_app(_mock_url_service(url_data))
    with TestClient(app) as client:
        resp = client.get("/abc1234")
    assert resp.status_code == 401
    assert "text/html" in resp.headers["content-type"]


def test_redirect_v2_wrong_password_returns_401_html():
    url_data = _make_url_cache(password_hash="$2b$12$hashed")
    app = _build_app(_mock_url_service(url_data))
    with TestClient(app, follow_redirects=False) as client:
        resp = client.get("/abc1234?password=wrongpassword")
    assert resp.status_code == 401
    assert "text/html" in resp.headers["content-type"]


def test_redirect_v1_correct_plaintext_password_redirects():
    url_data = _make_url_cache(
        password_hash="mypassword", schema="v1", long_url="https://example.com"
    )
    app = _build_app(_mock_url_service(url_data, schema="v1"))
    with TestClient(app, follow_redirects=False) as client:
        resp = client.get("/abc123?password=mypassword")
    assert resp.status_code == 302


def test_redirect_bad_user_agent_skips_analytics_but_redirects():
    """ValidationError from the sink = bad UA → skip analytics, still redirect."""
    url_data = _make_url_cache(long_url="https://example.com")
    sink = MagicMock()
    sink.emit = AsyncMock(side_effect=ValidationError("bad UA"))
    app = _build_app(_mock_url_service(url_data), sink)
    with TestClient(app, follow_redirects=False) as client:
        resp = client.get("/abc1234", headers={"User-Agent": ""})
    assert resp.status_code == 302


def test_redirect_sink_forbidden_blocks_redirect():
    """Defense in depth: ForbiddenError raised by the inline sink → 403."""
    url_data = _make_url_cache(
        schema="v1", long_url="https://example.com", block_bots=True
    )
    sink = MagicMock()
    sink.emit = AsyncMock(side_effect=ForbiddenError("bots not allowed"))
    app = _build_app(_mock_url_service(url_data, schema="v1"), sink)
    with TestClient(app) as client:
        resp = client.get("/abc123", headers={"User-Agent": BROWSER_UA})
    assert resp.status_code == 403
    assert "text/html" in resp.headers["content-type"]


def test_redirect_sink_unexpected_error_still_redirects():
    """A broken click pipeline must never take down the redirect."""
    url_data = _make_url_cache(long_url="https://example.com")
    sink = MagicMock()
    sink.emit = AsyncMock(side_effect=RuntimeError("pipeline exploded"))
    app = _build_app(_mock_url_service(url_data), sink)
    with TestClient(app, follow_redirects=False) as client:
        resp = client.get("/abc1234")
    assert resp.status_code == 302


# ── Pre-emit bot block tests ──────────────────────────────────────────────────


def test_v1_bot_blocked_before_emit():
    """block_bots v1 URL + bot UA → 403 decided in the route, no event emitted."""
    url_data = _make_url_cache(schema="v1", block_bots=True)
    sink = _mock_click_sink()
    app = _build_app(_mock_url_service(url_data, schema="v1"), sink)
    with TestClient(app) as client:
        resp = client.get("/abc123", headers={"User-Agent": BOT_UA})
    assert resp.status_code == 403
    sink.emit.assert_not_awaited()


def test_emoji_bot_blocked_before_emit():
    url_data = _make_url_cache(schema="v1", block_bots=True)
    sink = _mock_click_sink()
    app = _build_app(_mock_url_service(url_data, schema="emoji"), sink)
    with TestClient(app) as client:
        resp = client.get("/%F0%9F%90%8D", headers={"User-Agent": BOT_UA})
    assert resp.status_code == 403
    sink.emit.assert_not_awaited()


def test_v2_bot_not_blocked_at_route():
    """v2 bot handling stays in the pipeline: analytics skipped, not the redirect."""
    url_data = _make_url_cache(schema="v2", block_bots=True)
    sink = _mock_click_sink()
    app = _build_app(_mock_url_service(url_data), sink)
    with TestClient(app, follow_redirects=False) as client:
        resp = client.get("/abc1234", headers={"User-Agent": BOT_UA})
    assert resp.status_code == 302
    sink.emit.assert_awaited_once()


def test_v1_non_bot_not_blocked():
    url_data = _make_url_cache(schema="v1", block_bots=True)
    sink = _mock_click_sink()
    app = _build_app(_mock_url_service(url_data, schema="v1"), sink)
    with TestClient(app, follow_redirects=False) as client:
        resp = client.get("/abc123", headers={"User-Agent": BROWSER_UA})
    assert resp.status_code == 302
    sink.emit.assert_awaited_once()


def test_v1_bot_with_empty_ua_not_pre_blocked():
    """Empty UA can't be classified — matches inline behavior (ValidationError
    path: skip analytics, still redirect)."""
    url_data = _make_url_cache(schema="v1", block_bots=True)
    sink = _mock_click_sink()
    app = _build_app(_mock_url_service(url_data, schema="v1"), sink)
    with TestClient(app, follow_redirects=False) as client:
        resp = client.get("/abc123", headers={"User-Agent": ""})
    assert resp.status_code == 302


def test_redirect_head_skips_click_tracking():
    """HEAD requests skip analytics — nothing is emitted."""
    url_data = _make_url_cache(long_url="https://example.com")
    sink = _mock_click_sink()
    app = _build_app(_mock_url_service(url_data), sink)
    with TestClient(app, follow_redirects=False) as client:
        resp = client.head("/abc1234")
    assert resp.status_code == 302
    sink.emit.assert_not_awaited()


def test_head_bot_on_blocked_v1_still_not_pre_blocked():
    """HEAD is exempt from tracking AND from the pre-emit bot decision."""
    url_data = _make_url_cache(schema="v1", block_bots=True)
    sink = _mock_click_sink()
    app = _build_app(_mock_url_service(url_data, schema="v1"), sink)
    with TestClient(app, follow_redirects=False) as client:
        resp = client.head("/abc123", headers={"User-Agent": BOT_UA})
    assert resp.status_code == 302
    sink.emit.assert_not_awaited()


# ── Password form tests ───────────────────────────────────────────────────────


def test_password_form_correct_password_redirects():
    url_data = _make_url_cache(
        password_hash="mypassword", schema="v1", long_url="https://example.com"
    )
    app = _build_app(_mock_url_service(url_data, schema="v1"))
    with TestClient(app, follow_redirects=False) as client:
        resp = client.post("/abc123/password", data={"password": "mypassword"})
    assert resp.status_code == 302
    assert "password=mypassword" in resp.headers["location"]


def test_password_form_wrong_password_renders_password_html():
    url_data = _make_url_cache(
        password_hash="mypassword", schema="v1", long_url="https://example.com"
    )
    app = _build_app(_mock_url_service(url_data, schema="v1"))
    with TestClient(app) as client:
        resp = client.post("/abc123/password", data={"password": "wrongpassword"})
    # Re-renders password.html with error — 200 status
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]


def test_password_form_url_not_found_returns_400_html():
    url_svc = MagicMock()
    url_svc.resolve = AsyncMock(side_effect=NotFoundError("not found"))
    app = _build_app(url_svc)
    with TestClient(app) as client:
        resp = client.post("/noexist/password", data={"password": "pw"})
    assert resp.status_code == 400
    assert "text/html" in resp.headers["content-type"]


def test_password_form_url_not_password_protected_returns_400_html():
    url_data = _make_url_cache(password_hash=None, long_url="https://example.com")
    app = _build_app(_mock_url_service(url_data))
    with TestClient(app) as client:
        resp = client.post("/abc1234/password", data={"password": "pw"})
    assert resp.status_code == 400
    assert "text/html" in resp.headers["content-type"]
