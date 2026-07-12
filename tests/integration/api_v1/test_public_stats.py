"""Tests for GET|POST /api/v1/public/stats/{short_code}.

All rows of the contract matrix assert status code AND body. Repos are
dict-backed fakes; the click repo captures aggregation pipelines so the
url_id scoping is asserted on the real StatsService machinery.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from bson import ObjectId
from fastapi.testclient import TestClient

from dependencies import get_current_user
from dependencies.services import get_public_stats_service
from infrastructure.crypto import hash_password
from schemas.models.url import EmojiUrlDoc, LegacyUrlDoc, UrlV2Doc
from services.public_stats_service import PublicStatsService
from services.stats_service import StatsService

from .conftest import _build_test_app, _make_user

_DOMAIN = "spoo.me"
_NOT_FOUND_BODY = {"error": "short_code not found", "code": "not_found"}


# ── Document builders ─────────────────────────────────────────────────────────


def _make_v2_doc(alias: str = "abc1234", **overrides: Any) -> UrlV2Doc:
    data: dict[str, Any] = {
        "_id": ObjectId(),
        "alias": alias,
        "owner_id": ObjectId(),
        "domain": _DOMAIN,
        "created_at": datetime(2024, 1, 1, tzinfo=timezone.utc),
        "long_url": "https://example.com/long",
        "status": "ACTIVE",
        "private_stats": None,  # anonymous/unowned default — public
        "total_clicks": 0,
    }
    data.update(overrides)
    return UrlV2Doc(**data)


def _v1_data(code: str, **overrides: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "_id": code,
        "url": "https://example.com/legacy",
        "total-clicks": 20,
        "ips": [f"10.0.0.{i}" for i in range(8)],
        "counter": {},
        "unique_counter": {},
        "browser": {},
        "os_name": {},
        "country": {},
        "referrer": {},
        "bots": {},
        "average_redirection_time": 14.236,
        "last-click": "2026-01-06 10:00:00",
    }
    data.update(overrides)
    return data


def _make_v1_doc(code: str = "legacy", **overrides: Any) -> LegacyUrlDoc:
    return LegacyUrlDoc(**_v1_data(code, **overrides))


def _make_emoji_doc(code: str, **overrides: Any) -> EmojiUrlDoc:
    return EmojiUrlDoc(**_v1_data(code, **overrides))


# ── Dict-backed repo fakes ────────────────────────────────────────────────────


class _DictUrlRepo:
    """Stand-in for UrlRepository — (alias, domain)-keyed lookups."""

    def __init__(self, docs: list[UrlV2Doc] | None = None) -> None:
        self._docs = {(doc.alias, doc.domain): doc for doc in (docs or [])}

    async def find_by_alias(self, alias: str, domain: str) -> UrlV2Doc | None:
        return self._docs.get((alias, domain))


class _DictLegacyRepo:
    """Stand-in for Legacy/EmojiUrlRepository — _id-keyed lookups."""

    def __init__(self, docs: dict[str, Any] | None = None) -> None:
        self._docs = docs or {}

    async def find_by_id(self, short_code: str) -> Any | None:
        return self._docs.get(short_code)


class _CapturingClickRepo:
    """Records every aggregation pipeline; replays a canned $facet result."""

    def __init__(self, facet_result: dict[str, Any] | None = None) -> None:
        self.pipelines: list[list[dict[str, Any]]] = []
        self._facet_result = facet_result

    async def aggregate(self, pipeline: list[dict[str, Any]]) -> list[dict[str, Any]]:
        self.pipelines.append(pipeline)
        return [self._facet_result] if self._facet_result is not None else []


# ── App/service builders ──────────────────────────────────────────────────────


def _build_service(
    *,
    v2_docs: list[UrlV2Doc] | None = None,
    v1_docs: dict[str, LegacyUrlDoc] | None = None,
    emoji_docs: dict[str, EmojiUrlDoc] | None = None,
    click_repo: _CapturingClickRepo | None = None,
) -> tuple[PublicStatsService, _CapturingClickRepo]:
    click_repo = click_repo or _CapturingClickRepo()
    stats_service = StatsService(click_repo, _DictUrlRepo(), max_date_range_days=90)
    service = PublicStatsService(
        _DictUrlRepo(v2_docs),
        _DictLegacyRepo(v1_docs),
        _DictLegacyRepo(emoji_docs),
        stats_service,
        system_default_domain=_DOMAIN,
        max_date_range_days=90,
    )
    return service, click_repo


def _client(service: PublicStatsService, user: Any = None) -> TestClient:
    application = _build_test_app(
        {
            get_public_stats_service: lambda: service,
            get_current_user: lambda: user,
        }
    )
    return TestClient(application, raise_server_exceptions=True)


def _url(code: str, query: str = "") -> str:
    return f"/api/v1/public/stats/{code}{query}"


_WINDOW = "?start_date=2026-01-05T00:00:00Z&end_date=2026-01-06T23:59:59Z&timezone=UTC"


# ── 1. Missing and private answer byte-identically ────────────────────────────


def test_missing_and_private_stats_are_byte_identical_404s():
    service, _ = _build_service(
        v2_docs=[_make_v2_doc(alias="hidden1", private_stats=True)]
    )
    with _client(service) as client:
        missing = client.get(_url("absent9"))
        private = client.get(_url("hidden1"))

    assert missing.status_code == 404
    assert private.status_code == 404
    assert missing.json() == _NOT_FOUND_BODY
    assert missing.content == private.content  # no oracle


def test_explicitly_private_false_is_public():
    service, _ = _build_service(
        v2_docs=[_make_v2_doc(alias="open123", private_stats=False)]
    )
    with _client(service) as client:
        resp = client.get(_url("open123"))

    assert resp.status_code == 200
    assert resp.json()["generation"] == "v2"


# ── 2. Anonymous (private_stats=None) is public + link facts wire shape ──────


def test_anonymous_v2_is_public_with_lowercase_status_and_system_domain():
    service, _ = _build_service(v2_docs=[_make_v2_doc(alias="anonpub")])
    with _client(service) as client:
        resp = client.get(_url("anonpub"))

    assert resp.status_code == 200
    body = resp.json()
    assert body["generation"] == "v2"
    link = body["link"]
    assert link["alias"] == "anonpub"
    assert link["status"] == "active"  # LOWERCASE on the wire
    assert link["short_url"] == f"https://{_DOMAIN}/anonpub"
    assert link["long_url"] == "https://example.com/long"
    assert link["created_at"].startswith("2024-01-01")
    assert link["max_clicks"] is None
    assert link["block_bots"] is False
    assert link["password_protected"] is False


def test_blocked_status_is_lowercase_and_hides_long_url():
    service, _ = _build_service(
        v2_docs=[_make_v2_doc(alias="blocked1", status="BLOCKED")]
    )
    with _client(service) as client:
        resp = client.get(_url("blocked1"))

    assert resp.status_code == 200
    link = resp.json()["link"]
    assert link["status"] == "blocked"
    assert link["long_url"] is None


# ── 3. Owner bypass ───────────────────────────────────────────────────────────


def test_owner_session_bypasses_private_and_password_gates():
    owner_id = ObjectId()
    doc = _make_v2_doc(
        alias="mine123",
        owner_id=owner_id,
        private_stats=True,
        password=hash_password("sesame"),
    )
    service, _ = _build_service(v2_docs=[doc])
    with _client(service, user=_make_user(user_id=owner_id)) as client:
        resp = client.get(_url("mine123"))

    assert resp.status_code == 200
    assert resp.json()["link"]["password_protected"] is True


def test_owner_gets_long_url_on_non_active_link():
    owner_id = ObjectId()
    doc = _make_v2_doc(
        alias="paused1",
        owner_id=owner_id,
        private_stats=True,
        status="INACTIVE",
    )
    service, _ = _build_service(v2_docs=[doc])
    with _client(service, user=_make_user(user_id=owner_id)) as client:
        resp = client.get(_url("paused1"))

    assert resp.status_code == 200
    link = resp.json()["link"]
    assert link["status"] == "inactive"
    assert link["long_url"] == "https://example.com/long"


def test_non_owner_session_gets_the_same_404_for_private_stats():
    doc = _make_v2_doc(alias="hidden1", private_stats=True)
    service, _ = _build_service(v2_docs=[doc])
    with _client(service, user=_make_user()) as client:
        resp = client.get(_url("hidden1"))

    assert resp.status_code == 404
    assert resp.json() == _NOT_FOUND_BODY


# ── 4. v2 password gate (argon2) ─────────────────────────────────────────────


def test_v2_password_gates():
    doc = _make_v2_doc(alias="locked1", password=hash_password("sesame"))
    service, _ = _build_service(v2_docs=[doc])
    with _client(service) as client:
        no_password = client.get(_url("locked1"))
        assert no_password.status_code == 401
        assert no_password.json()["code"] == "password_required"

        # Passwords never ride URLs: a GET query-string password is IGNORED.
        query_password = client.get(_url("locked1", "?password=sesame"))
        assert query_password.status_code == 401
        assert query_password.json()["code"] == "password_required"

        empty_body = client.post(_url("locked1"))
        assert empty_body.status_code == 401
        assert empty_body.json()["code"] == "password_required"

        wrong = client.post(_url("locked1"), json={"password": "wrong"})
        assert wrong.status_code == 401
        assert wrong.json() == {
            "error": "incorrect password",
            "code": "invalid_password",
        }

        right = client.post(_url("locked1"), json={"password": "sesame"})
        assert right.status_code == 200
        assert right.json()["link"]["password_protected"] is True


# ── 5. v1 password gate (plaintext) ──────────────────────────────────────────


def test_v1_password_gates():
    doc = _make_v1_doc("legacy", password="hunter2")
    service, _ = _build_service(v1_docs={"legacy": doc})
    with _client(service) as client:
        no_password = client.get(_url("legacy"))
        assert no_password.status_code == 401
        assert no_password.json()["code"] == "password_required"

        wrong = client.post(_url("legacy"), json={"password": "wrong"})
        assert wrong.status_code == 401
        assert wrong.json()["code"] == "invalid_password"

        right = client.post(_url("legacy"), json={"password": "hunter2"})
        assert right.status_code == 200
        assert right.json()["generation"] == "v1"


# ── 6. v1 wire synthesis ─────────────────────────────────────────────────────


def test_v1_wire_shape():
    doc = _make_v1_doc(
        "legacy",
        **{
            "browser": {
                "Chrome": {"counts": 12, "ips": ["1.1.1.1", "2.2.2.2", "1.1.1.1"]},
                "Firefox": {"counts": 8, "ips": ["3.3.3.3"]},
            },
            "os_name": {"Windows": {"counts": 20, "ips": ["1.1.1.1"]}},
            "country": {
                "United States": {"counts": 15, "ips": ["1.1.1.1"]},
                "India": {"counts": 5, "ips": ["3.3.3.3"]},
            },
            "referrer": {"google_com": {"counts": 9, "ips": ["1.1.1.1"]}},
            "bots": {"Googlebot": 3, "Bingbot": 1},
            "counter": {
                "2026-01-04": 3,
                "2026-01-05": 5,
                "2026-01-06": 7,
                "2026-01-07": 2,
            },
            "unique_counter": {"2026-01-05": 2, "2026-01-06": 4},
        },
    )
    service, _ = _build_service(v1_docs={"legacy": doc})
    with _client(service) as client:
        resp = client.get(_url("legacy", _WINDOW))

    assert resp.status_code == 200
    body = resp.json()
    assert body["generation"] == "v1"
    stats = body["stats"]
    metrics = stats["metrics"]

    # v1 emits bots, never city; the os wire key is "os", not "os_name".
    assert "clicks_by_bots" in metrics
    assert "clicks_by_city" not in metrics
    assert "unique_clicks_by_city" not in metrics
    assert "clicks_by_os_name" not in metrics

    # Dimensions are LIFETIME (window only trims the time series).
    assert metrics["clicks_by_browser"] == [
        {"browser": "Chrome", "clicks": 12, "clicks_percentage": 60.0},
        {"browser": "Firefox", "clicks": 8, "clicks_percentage": 40.0},
    ]
    assert metrics["unique_clicks_by_browser"] == [
        {"browser": "Chrome", "unique_clicks": 2, "unique_clicks_percentage": 66.67},
        {"browser": "Firefox", "unique_clicks": 1, "unique_clicks_percentage": 33.33},
    ]
    assert metrics["clicks_by_os"] == [
        {"os": "Windows", "clicks": 20, "clicks_percentage": 100.0}
    ]

    # Country display names → ISO alpha-2, so flags render like v2.
    assert metrics["clicks_by_country"] == [
        {"country": "US", "clicks": 15, "clicks_percentage": 75.0},
        {"country": "IN", "clicks": 5, "clicks_percentage": 25.0},
    ]

    assert metrics["clicks_by_bots"] == [
        {"bots": "Googlebot", "clicks": 3, "clicks_percentage": 75.0},
        {"bots": "Bingbot", "clicks": 1, "clicks_percentage": 25.0},
    ]

    # Time series IS windowed ([2026-01-05, 2026-01-06]), ascending.
    assert metrics["clicks_by_time"] == [
        {"time": "2026-01-05", "clicks": 5, "clicks_percentage": 41.67},
        {"time": "2026-01-06", "clicks": 7, "clicks_percentage": 58.33},
    ]
    assert metrics["unique_clicks_by_time"] == [
        {"time": "2026-01-05", "unique_clicks": 2, "unique_clicks_percentage": 33.33},
        {"time": "2026-01-06", "unique_clicks": 4, "unique_clicks_percentage": 66.67},
    ]

    summary = stats["summary"]
    assert summary["total_clicks"] == 20  # lifetime
    assert summary["unique_clicks"] == 8  # len(ips)
    assert summary["first_click"] is None  # not stored on v1
    assert summary["last_click"].startswith("2026-01-06T10:00:00")
    assert summary["avg_redirection_time"] == 14.24

    assert stats["time_bucket_info"] == {
        "strategy": "daily",
        "interval_minutes": 1440,
        "display_format": "%Y-%m-%d",
        "mongo_format": "%Y-%m-%d",
        "timezone": "UTC",
    }
    assert stats["computed_metrics"] == {
        "unique_click_rate": 40.0,
        "repeat_click_rate": 60.0,
        "average_clicks_per_visitor": 2.5,
    }
    assert stats["scope"] == "anon"
    assert stats["short_code"] == "legacy"
    assert stats["group_by"] == ["time", "browser", "os", "country", "referrer"]
    assert "generated_at" in stats


# ── 7. v2 wire reuses the stats machinery, scoped by url_id ──────────────────


def test_v2_wire_scopes_match_by_url_id_not_short_code():
    doc = _make_v2_doc(alias="abc1234")
    first_click = datetime(2026, 1, 5, 8, 0, tzinfo=timezone.utc)
    facet_result = {
        "_summary": [
            {
                "total_clicks": 10,
                "unique_clicks": 4,
                "first_click": first_click,
                "last_click": first_click + timedelta(days=1),
                "avg_redirection_time": 12.0,
            }
        ],
        "time": [{"_id": "2026-01-05", "total_clicks": 10, "unique_clicks": 4}],
        "browser": [{"_id": "Chrome", "total_clicks": 6, "unique_clicks": 3}],
        "country": [{"_id": "Germany", "total_clicks": 10, "unique_clicks": 4}],
        "city": [{"_id": "Berlin", "total_clicks": 10, "unique_clicks": 4}],
    }
    service, click_repo = _build_service(
        v2_docs=[doc], click_repo=_CapturingClickRepo(facet_result)
    )
    with _client(service) as client:
        resp = client.get(_url("abc1234", _WINDOW))

    assert resp.status_code == 200
    body = resp.json()
    assert body["generation"] == "v2"
    stats = body["stats"]
    metrics = stats["metrics"]

    # v2 emits city, never bots.
    assert metrics["clicks_by_city"] == [
        {"city": "Berlin", "clicks": 10, "clicks_percentage": 100.0}
    ]
    assert "clicks_by_bots" not in metrics
    assert metrics["clicks_by_browser"][0] == {
        "browser": "Chrome",
        "clicks": 6,
        "clicks_percentage": 100.0,
    }
    assert metrics["clicks_by_country"] == [
        {"country": "DE", "clicks": 10, "clicks_percentage": 100.0}
    ]
    assert stats["summary"]["total_clicks"] == 10
    assert stats["group_by"] == ["time", "browser", "os", "country", "city", "referrer"]

    # The $match is scoped by meta.url_id — never meta.short_code — so a
    # same-alias link on a custom domain can never bleed in.
    assert len(click_repo.pipelines) == 1
    match = click_repo.pipelines[0][0]["$match"]
    assert match["meta.url_id"] == doc.id
    assert "meta.short_code" not in match
    assert set(match) == {"meta.url_id", "clicked_at"}


# ── 8. Effective status is derived (read-only) ───────────────────────────────


def test_v2_active_with_past_expire_after_reports_expired_and_hides_long_url():
    doc = _make_v2_doc(
        alias="oldlink",
        expire_after=datetime.now(timezone.utc) - timedelta(days=1),
    )
    service, _ = _build_service(v2_docs=[doc])
    with _client(service) as client:
        resp = client.get(_url("oldlink"))

    assert resp.status_code == 200
    link = resp.json()["link"]
    assert link["status"] == "expired"
    assert link["long_url"] is None


def test_v2_active_with_max_clicks_reached_reports_expired():
    doc = _make_v2_doc(alias="capped1", max_clicks=5, total_clicks=5)
    service, _ = _build_service(v2_docs=[doc])
    with _client(service) as client:
        resp = client.get(_url("capped1"))

    assert resp.status_code == 200
    link = resp.json()["link"]
    assert link["status"] == "expired"
    assert link["long_url"] is None


def test_v1_max_clicks_reached_reports_expired():
    doc = _make_v1_doc("legacy", **{"max-clicks": 20, "total-clicks": 20})
    service, _ = _build_service(v1_docs={"legacy": doc})
    with _client(service) as client:
        resp = client.get(_url("legacy"))

    assert resp.status_code == 200
    link = resp.json()["link"]
    assert link["status"] == "expired"
    assert link["long_url"] is None
    assert link["max_clicks"] == 20


# ── 9. Emoji aliases resolve and collapse to v1 ──────────────────────────────


def test_emoji_alias_resolves_as_v1():
    doc = _make_emoji_doc("🚀", url="https://docs.spoo.me/emoji-urls")
    service, _ = _build_service(emoji_docs={"🚀": doc})
    with _client(service) as client:
        resp = client.get(_url("🚀"))

    assert resp.status_code == 200
    body = resp.json()
    assert body["generation"] == "v1"
    link = body["link"]
    assert link["alias"] == "🚀"
    assert link["short_url"] == f"https://{_DOMAIN}/🚀"
    assert link["long_url"] == "https://docs.spoo.me/emoji-urls"
    assert link["created_at"] is None  # never stored on v1/emoji docs


# ── 10. Resolution order + validation ────────────────────────────────────────


def test_six_char_alias_falls_back_to_v2():
    doc = _make_v2_doc(alias="sixsix")
    service, _ = _build_service(v2_docs=[doc])
    with _client(service) as client:
        resp = client.get(_url("sixsix"))

    assert resp.status_code == 200
    assert resp.json()["generation"] == "v2"


def test_inverted_date_range_is_a_validation_error():
    service, _ = _build_service(v2_docs=[_make_v2_doc(alias="anonpub")])
    with _client(service) as client:
        resp = client.get(
            _url(
                "anonpub",
                "?start_date=2026-01-10T00:00:00Z&end_date=2026-01-05T00:00:00Z",
            )
        )

    assert resp.status_code == 400
    assert resp.json()["code"] == "validation_error"
