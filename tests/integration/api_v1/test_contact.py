"""Tests for POST /api/v1/contact — the JSON twin of the Jinja form.

ContactService is REAL (the endpoint reuses ``send_contact_message``
verbatim); the webhook and captcha are capturing fakes so the legacy
Discord embed shape is pinned exactly. Settings are injected per test to
drive the configured/unconfigured branches.

Note on validation statuses: DTO shape failures (invalid email, empty
message) return 422 with ``code: validation_error`` via the global
handler — the codebase-wide convention every /api/v1 endpoint follows.
The TRD sketched 400 for these; the body shape and ``code`` are
identical, only the status differs. Semantic gates (missing captcha
token when captcha is configured) stay 400.
"""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

from config import AppSettings
from dependencies import get_contact_service
from middleware.rate_limiter import limiter
from routes.api_v1 import router as api_v1_router
from services.contact_service import ContactService
from tests.conftest import build_test_app

_URL = "/api/v1/contact"


@pytest.fixture(autouse=True)
def _reset_limiter_between_tests():
    """POST /api/v1/contact rides Limits.CONTACT (5/min) — clear the
    in-memory counters so tests never eat each other's budget."""
    limiter.reset()
    yield
    limiter.reset()


# ── Fakes ─────────────────────────────────────────────────────────────────────


class _FakeWebhook:
    def __init__(self, ok: bool = True) -> None:
        self.ok = ok
        self.payloads: list[dict[str, Any]] = []

    async def send(self, payload: dict[str, Any]) -> bool:
        self.payloads.append(payload)
        return self.ok


class _FakeCaptcha:
    def __init__(self, ok: bool = True) -> None:
        self.ok = ok
        self.tokens: list[str] = []

    async def verify(self, token: str) -> bool:
        self.tokens.append(token)
        return self.ok


# ── App builder ───────────────────────────────────────────────────────────────


def _client(
    *,
    contact_webhook: str = "https://hooks.test/contact",
    sitekey: str = "test-sitekey",
    webhook: _FakeWebhook | None = None,
    captcha: _FakeCaptcha | None = None,
) -> TestClient:
    webhook = webhook if webhook is not None else _FakeWebhook()
    captcha = captcha if captcha is not None else _FakeCaptcha()
    service = ContactService(webhook, _FakeWebhook(), captcha)
    settings = AppSettings(
        contact_webhook=contact_webhook,
        hcaptcha_sitekey=sitekey,
    )
    app = build_test_app(
        api_v1_router,
        overrides={get_contact_service: lambda: service},
        extra_state={"settings": settings},
    )
    return TestClient(app)


def _body(**overrides: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "email": "reporter@example.com",
        "message": "hello there",
        "captcha_token": "tok",
    }
    body.update(overrides)
    return body


# ── Happy path ────────────────────────────────────────────────────────────────


def test_contact_happy_path_sends_exact_legacy_embed():
    webhook = _FakeWebhook()
    captcha = _FakeCaptcha()
    with _client(webhook=webhook, captcha=captcha) as c:
        resp = c.post(_URL, json=_body())

    assert resp.status_code == 200
    assert resp.json() == {"ok": True}

    assert captcha.tokens == ["tok"]
    assert len(webhook.payloads) == 1
    embed = webhook.payloads[0]["embeds"][0]
    assert embed["title"] == "New Contact Message ✉️"
    assert embed["color"] == 9103397
    assert embed["fields"] == [
        {"name": "Email", "value": "```reporter@example.com```"},
        {"name": "Message", "value": "```hello there```"},
    ]
    assert embed["footer"] == {
        "text": "spoo-me",
        "icon_url": "https://spoo.me/static/images/favicon.png",
    }
    assert "timestamp" in embed


# ── Captcha semantics (mirror the Jinja form) ─────────────────────────────────


def test_contact_missing_captcha_when_configured_400():
    webhook = _FakeWebhook()
    captcha = _FakeCaptcha()
    with _client(webhook=webhook, captcha=captcha) as c:
        resp = c.post(_URL, json=_body(captcha_token=None))

    assert resp.status_code == 400
    body = resp.json()
    assert body["code"] == "validation_error"
    assert "captcha" in body["error"].lower()
    # Rejected before any service work.
    assert captcha.tokens == []
    assert webhook.payloads == []


def test_contact_captcha_not_required_when_unconfigured():
    webhook = _FakeWebhook()
    with _client(sitekey="", webhook=webhook) as c:
        resp = c.post(_URL, json=_body(captcha_token=None))

    assert resp.status_code == 200
    assert resp.json() == {"ok": True}
    assert len(webhook.payloads) == 1


def test_contact_captcha_failure_403():
    webhook = _FakeWebhook()
    with _client(captcha=_FakeCaptcha(ok=False), webhook=webhook) as c:
        resp = c.post(_URL, json=_body())

    assert resp.status_code == 403
    assert resp.json() == {
        "error": "Invalid captcha, please try again",
        "code": "forbidden",
    }
    assert webhook.payloads == []


# ── Not configured / failure branches ─────────────────────────────────────────


def test_contact_webhook_unset_503():
    with _client(contact_webhook="") as c:
        resp = c.post(_URL, json=_body())

    assert resp.status_code == 503
    body = resp.json()
    assert body["code"] == "not_configured"
    assert body["error"]


def test_contact_webhook_send_failure_500():
    with _client(webhook=_FakeWebhook(ok=False)) as c:
        resp = c.post(_URL, json=_body())

    assert resp.status_code == 500
    assert resp.json()["code"] == "internal_error"


# ── Shape validation ──────────────────────────────────────────────────────────


def test_contact_invalid_email_is_validation_error():
    with _client() as c:
        resp = c.post(_URL, json=_body(email="not-an-email"))

    assert resp.status_code == 422
    body = resp.json()
    assert body["code"] == "validation_error"
    assert body["field"] == "email"


def test_contact_empty_message_is_validation_error():
    with _client() as c:
        resp = c.post(_URL, json=_body(message=""))

    assert resp.status_code == 422
    assert resp.json()["code"] == "validation_error"


def test_contact_message_over_4000_chars_is_validation_error():
    with _client() as c:
        resp = c.post(_URL, json=_body(message="x" * 4001))

    assert resp.status_code == 422
    assert resp.json()["code"] == "validation_error"
