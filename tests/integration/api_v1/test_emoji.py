"""Tests for GET /api/v1/emoji-set.

Public, unauthenticated read of the emoji-alias acceptance policy. The
endpoint reads only settings and the pure ``shared.emoji_policy``
derivation, so no repo mocks are needed — the real AppSettings from the
test lifespan drives it.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from config import AppSettings
from shared.emoji_policy import check_emoji_alias

from .conftest import _build_test_app

# Known-safe single-codepoint emoji.
STAR = "⭐"
PARTY = "\U0001f389"  # 🎉
# Known-rejected forms.
US_FLAG = "\U0001f1fa\U0001f1f8"  # 🇺🇸 regional-indicator flag
WOMAN_TECHNOLOGIST = "\U0001f469‍\U0001f4bb"  # 👩‍💻 ZWJ family
KEYCAP_ONE = "1️⃣"  # 1️⃣ keycap
SMILEY_TEXT_DEFAULT = "☺"  # text-default without VS16


def _get():
    application = _build_test_app({})
    with TestClient(application, raise_server_exceptions=False) as client:
        return client.get("/api/v1/emoji-set")


def test_returns_200_unauthenticated():
    resp = _get()
    assert resp.status_code == 200


def test_response_shape():
    body = _get().json()
    assert set(body) == {
        "accept_max_version",
        "generate_max_version",
        "max_graphemes",
        "accepted",
        "generate",
    }
    assert isinstance(body["accepted"], list)
    assert isinstance(body["generate"], list)


def test_caps_and_max_graphemes_match_settings():
    settings = AppSettings()
    body = _get().json()
    assert body["accept_max_version"] == settings.emoji_accept_max_version
    assert body["generate_max_version"] == settings.emoji_generate_max_version
    assert body["max_graphemes"] == settings.max_emoji_alias_length


def test_accepted_non_empty_and_contains_known_safe_emoji():
    accepted = _get().json()["accepted"]
    assert len(accepted) > 0
    assert STAR in accepted
    assert PARTY in accepted


def test_generate_is_within_the_safe_space():
    body = _get().json()
    accepted, generate = set(body["accepted"]), body["generate"]
    assert len(generate) > 0
    # The generation pool is a subset of the accepted picker list.
    assert set(generate) <= accepted
    # And every generated entry is itself an accepted single-codepoint alias.
    for e in generate:
        assert check_emoji_alias(e) == "ok"


def test_accepted_excludes_known_rejected_forms():
    accepted = set(_get().json()["accepted"])
    assert US_FLAG not in accepted  # regional-indicator flag
    assert WOMAN_TECHNOLOGIST not in accepted  # ZWJ family
    assert KEYCAP_ONE not in accepted  # keycap
    assert SMILEY_TEXT_DEFAULT not in accepted  # text-default, needs VS16


def test_accepted_excludes_anything_the_policy_would_reject():
    # Nothing the picker offers may be something the create endpoint 400s:
    # the derivation agrees with the validator for the whole sample.
    accept_cap = AppSettings().emoji_accept_max_version
    for e in _get().json()["accepted"]:
        assert check_emoji_alias(e, max_version=accept_cap) == "ok"


def test_cache_control_header():
    resp = _get()
    assert resp.headers["cache-control"] == (
        "public, max-age=86400, stale-while-revalidate=604800"
    )


def test_etag_present_and_stable():
    first, second = _get(), _get()
    assert first.headers.get("etag")
    assert first.headers["etag"] == second.headers["etag"]


def test_conditional_request_returns_304():
    etag = _get().headers["etag"]
    application = _build_test_app({})
    with TestClient(application, raise_server_exceptions=False) as client:
        resp = client.get("/api/v1/emoji-set", headers={"If-None-Match": etag})
    assert resp.status_code == 304
    assert not resp.content
