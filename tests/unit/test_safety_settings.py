"""Unit tests for SafetySettings."""

from __future__ import annotations

import pytest
from pydantic import ValidationError as PydanticValidationError

from config import AppSettings, SafetySettings


class TestSafetySettings:
    def test_defaults_are_off_and_safe(self):
        s = SafetySettings()
        assert s.enabled is False
        assert s.stream == "events:safety"
        assert s.dlq_stream == "events:safety:dlq"
        assert s.reverdict_ttl_hours == 24

    def test_env_prefix(self, monkeypatch):
        monkeypatch.setenv("SAFETY_ENABLED", "true")
        monkeypatch.setenv("SAFETY_REVERDICT_TTL_HOURS", "6")
        s = SafetySettings()
        assert s.enabled is True
        assert s.reverdict_ttl_hours == 6

    def test_unprefixed_env_vars_are_ignored(self, monkeypatch):
        monkeypatch.setenv("ENABLED", "true")
        assert SafetySettings().enabled is False

    def test_invalid_tunables_rejected(self):
        with pytest.raises(PydanticValidationError):
            SafetySettings(reverdict_ttl_hours=0)
        with pytest.raises(PydanticValidationError):
            SafetySettings(maxlen=10)

    def test_populated_on_app_settings(self):
        settings = AppSettings()
        assert isinstance(settings.safety, SafetySettings)
