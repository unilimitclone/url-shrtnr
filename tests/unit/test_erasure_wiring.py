"""Env-gated selection of the erasure mailer and PostHog eraser.

``build_erasure_mailer`` / ``build_posthog_eraser`` pick the real
integration when its settings are configured and the Noop otherwise —
AppSettings is env-only, so both branches are probed via env vars.
"""

from unittest.mock import MagicMock

import pytest

from config import AppSettings
from dependencies.wiring import build_erasure_mailer, build_posthog_eraser
from infrastructure.email.zeptomail import ZeptoMailProvider
from infrastructure.posthog_erasure import HttpPostHogEraser
from services.account_erasure_service import (
    NoopErasureMailer,
    NoopPostHogEraser,
)


@pytest.fixture
def base_env(monkeypatch):
    monkeypatch.setenv("MONGODB_URI", "mongodb://localhost:27017/")
    monkeypatch.delenv("ZEPTO_API_TOKEN", raising=False)
    monkeypatch.delenv("POSTHOG_ERASURE_API_KEY", raising=False)
    monkeypatch.delenv("POSTHOG_ERASURE_PROJECT_ID", raising=False)
    monkeypatch.delenv("POSTHOG_ERASURE_HOST", raising=False)
    return monkeypatch


class TestBuildErasureMailer:
    def test_unconfigured_token_selects_noop(self, base_env):
        mailer = build_erasure_mailer(AppSettings(), MagicMock())
        assert isinstance(mailer, NoopErasureMailer)

    def test_configured_token_selects_zepto(self, base_env):
        base_env.setenv("ZEPTO_API_TOKEN", "test-token")
        mailer = build_erasure_mailer(AppSettings(), MagicMock())
        assert isinstance(mailer, ZeptoMailProvider)

    def test_existing_provider_singleton_reused(self, base_env):
        base_env.setenv("ZEPTO_API_TOKEN", "test-token")
        provider = MagicMock(spec=ZeptoMailProvider)
        mailer = build_erasure_mailer(
            AppSettings(), MagicMock(), email_provider=provider
        )
        assert mailer is provider

    def test_unconfigured_ignores_passed_provider(self, base_env):
        # No token ⇒ Noop even when the app already built a provider.
        provider = MagicMock(spec=ZeptoMailProvider)
        mailer = build_erasure_mailer(
            AppSettings(), MagicMock(), email_provider=provider
        )
        assert isinstance(mailer, NoopErasureMailer)


class TestBuildPostHogEraser:
    def test_unconfigured_selects_noop(self, base_env):
        eraser = build_posthog_eraser(AppSettings(), MagicMock())
        assert isinstance(eraser, NoopPostHogEraser)

    def test_key_without_project_id_selects_noop(self, base_env):
        base_env.setenv("POSTHOG_ERASURE_API_KEY", "phx_secret")
        eraser = build_posthog_eraser(AppSettings(), MagicMock())
        assert isinstance(eraser, NoopPostHogEraser)

    def test_configured_selects_http_eraser(self, base_env):
        base_env.setenv("POSTHOG_ERASURE_API_KEY", "phx_secret")
        base_env.setenv("POSTHOG_ERASURE_PROJECT_ID", "12345")
        eraser = build_posthog_eraser(AppSettings(), MagicMock())
        assert isinstance(eraser, HttpPostHogEraser)
        assert eraser._project_id == "12345"
        assert eraser._host == "https://eu.posthog.com"

    def test_host_override(self, base_env):
        base_env.setenv("POSTHOG_ERASURE_API_KEY", "phx_secret")
        base_env.setenv("POSTHOG_ERASURE_PROJECT_ID", "12345")
        base_env.setenv("POSTHOG_ERASURE_HOST", "https://us.posthog.com/")
        eraser = build_posthog_eraser(AppSettings(), MagicMock())
        assert isinstance(eraser, HttpPostHogEraser)
        assert eraser._host == "https://us.posthog.com"
