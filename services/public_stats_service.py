"""
PublicStatsService — public per-link statistics for the /stats/{code} page.

Resolves a short code across BOTH URL generations (``urlsV2``, legacy
``urls``, ``emojis``) scoped to the system default domain, enforces the
public-page privacy rules, and returns link facts plus the modern stats
wire shape (identical keys to GET /api/v1/stats).

Privacy semantics (frozen contract):
  - a v2 link with private stats answers BYTE-IDENTICALLY to a missing
    code (no oracle distinguishing "private" from "absent");
  - password-protected links answer 401 ``password_required`` until the
    password arrives in a POST body; a wrong password is 401
    ``invalid_password``; a password never rides a URL;
  - an authenticated owner bypasses both the privacy and password gates.

v2 analytics reuse StatsService's aggregation machinery scoped by
``meta.url_id`` (never ``meta.short_code`` — a same-alias link on a custom
domain must not bleed in). v1/emoji analytics are synthesized into the
same wire shape from the embedded document counters: dimensions are
LIFETIME totals (that's all v1 stores), only the daily time series is
windowed.

Framework-agnostic: no FastAPI imports. Status is derived READ-ONLY —
this service never writes.
"""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import unquote
from zoneinfo import available_timezones

from bson import ObjectId

from errors import (
    InvalidPasswordError,
    NotFoundError,
    PasswordRequiredError,
    ValidationError,
)
from infrastructure.crypto import verify_password
from infrastructure.logging import get_logger
from repositories.legacy.emoji_url_repository import EmojiUrlRepository
from repositories.legacy.legacy_url_repository import LegacyUrlRepository
from repositories.url_repository import UrlRepository
from schemas.enums.stats import StatsScope
from schemas.models.url import (
    EmojiUrlDoc,
    LegacyUrlDoc,
    SchemaVersion,
    UrlStatus,
    UrlV2Doc,
)
from services.stats_service import _TIMEZONE_ALIASES, StatsService
from shared.aggregation_strategies import convert_country_name
from shared.datetime_utils import parse_datetime
from shared.validators import is_emoji_alias

log = get_logger(__name__)

_PublicDoc = UrlV2Doc | LegacyUrlDoc | EmojiUrlDoc

# Dimensions are FIXED per generation (no group_by on the wire). v1 never
# emits city (not stored); v2 never emits bots (tracked per-click, not as
# a dimension the public page shows).
_V2_GROUP_BY = ["time", "browser", "os", "country", "city", "referrer"]
_V1_GROUP_BY = ["time", "browser", "os", "country", "referrer"]
_METRICS = ["clicks", "unique_clicks"]

_V1_LAST_CLICK_FORMAT = "%Y-%m-%d %H:%M:%S"


def _as_utc(dt: datetime | None) -> datetime | None:
    """Make a stored datetime timezone-aware (BSON datetimes are naive UTC)."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


class PublicStatsService:
    """Public stats query service.

    Args:
        url_repo:              Repository for the ``urlsV2`` collection.
        legacy_repo:           Repository for the legacy ``urls`` collection.
        emoji_repo:            Repository for the ``emojis`` collection.
        stats_service:         The shared StatsService (v2 aggregation reuse).
        system_default_domain: Canonical fqdn — resolution is scoped to it;
                               custom-tenant aliases never resolve here.
        max_date_range_days:   Maximum allowed date range in days.
    """

    def __init__(
        self,
        url_repo: UrlRepository,
        legacy_repo: LegacyUrlRepository,
        emoji_repo: EmojiUrlRepository,
        stats_service: StatsService,
        *,
        system_default_domain: str,
        max_date_range_days: int = 90,
    ) -> None:
        self._url_repo = url_repo
        self._legacy_repo = legacy_repo
        self._emoji_repo = emoji_repo
        self._stats = stats_service
        self._system_default_domain = system_default_domain
        self._max_date_range_days = max_date_range_days

    # ── Public API ────────────────────────────────────────────────────────────

    async def get_public_stats(
        self,
        short_code: str,
        *,
        start_date: str | None = None,
        end_date: str | None = None,
        tz_name: str = "UTC",
        password: str | None = None,
        user_id: ObjectId | None = None,
    ) -> dict[str, Any]:
        """Resolve a short code and return its public stats payload.

        Args:
            short_code: Path alias (may arrive percent-encoded — emoji).
            start_date: ISO datetime string; defaults to end_date - 7 days.
            end_date:   ISO datetime string; defaults to now.
            tz_name:    IANA timezone for bucketing/formatting.
            password:   Password from a POST body (never from a URL).
            user_id:    Authenticated user id, if any (owner bypass).

        Returns:
            ``{"generation", "link", "stats"}`` ready for the response DTO.

        Raises:
            NotFoundError:         Unknown code — or private stats
                                   (byte-identical body, no oracle).
            PasswordRequiredError: Password set, none supplied (401).
            InvalidPasswordError:  Password set, wrong one supplied (401).
            ValidationError:       Bad dates / range too large.
        """
        started = time.perf_counter()
        code = unquote(short_code)

        doc, schema = await self._resolve(code)
        if doc is None:
            raise NotFoundError("short_code not found")

        is_v2 = schema == SchemaVersion.V2
        generation = "v2" if is_v2 else "v1"

        # Owner bypass rides the same request. The anonymous sentinel
        # owner_id can never equal a real user id, so no special-casing.
        is_owner = bool(is_v2 and user_id is not None and doc.owner_id == user_id)

        # Private stats answer exactly like a missing code. Semantics:
        # True = private (owned default), None = anonymous/unowned = public,
        # False = explicitly public. v1/emoji have no flag — always public.
        if is_v2 and doc.private_stats and not is_owner:
            log.info("public_stats_denied", reason="private_stats", short_code=code)
            raise NotFoundError("short_code not found")

        if not is_owner and doc.password:
            if not password:
                log.info(
                    "public_stats_denied",
                    reason="password_required",
                    short_code=code,
                )
                raise PasswordRequiredError("this link's stats are password protected")
            if not self._password_matches(doc, is_v2, password):
                log.info(
                    "public_stats_denied",
                    reason="invalid_password",
                    short_code=code,
                )
                raise InvalidPasswordError("incorrect password")

        window_start, window_end, tz_name = self._resolve_window(
            start_date, end_date, tz_name
        )

        alias = doc.alias if is_v2 else code
        now = datetime.now(timezone.utc)
        status = self._effective_status(doc, is_v2, now)
        link = self._link_facts(doc, alias, status, is_v2=is_v2, is_owner=is_owner)

        if is_v2:
            stats = await self._query_v2_stats(doc, window_start, window_end, tz_name)
        else:
            stats = self._synthesize_v1_stats(
                doc, alias, window_start, window_end, tz_name
            )

        duration_ms = int((time.perf_counter() - started) * 1000)
        log.info(
            "public_stats_query",
            short_code=alias,
            generation=generation,
            status=status,
            owner_bypass=is_owner,
            start_date=window_start.isoformat(),
            end_date=window_end.isoformat(),
            total_clicks=stats.get("summary", {}).get("total_clicks", 0),
            duration_ms=duration_ms,
        )

        return {"generation": generation, "link": link, "stats": stats}

    # ── Private: resolution ───────────────────────────────────────────────────

    async def _resolve(self, code: str) -> tuple[_PublicDoc | None, SchemaVersion]:
        """Domain-scoped dispatch, mirroring UrlService._dispatch.

        emoji → emojis only; 7 chars → urlsV2 then urls; 6 chars → urls
        then urlsV2; anything else → urlsV2 then urls. v2 lookups are
        scoped to the system default domain; v1/emoji only exist there —
        custom-tenant aliases never resolve on this endpoint.
        """
        if is_emoji_alias(code):
            return await self._emoji_repo.find_by_id(code), SchemaVersion.EMOJI

        if len(code) == 6:
            v1_doc = await self._legacy_repo.find_by_id(code)
            if v1_doc is not None:
                return v1_doc, SchemaVersion.V1
            v2_doc = await self._url_repo.find_by_alias(
                code, self._system_default_domain
            )
            return v2_doc, SchemaVersion.V2

        v2_doc = await self._url_repo.find_by_alias(code, self._system_default_domain)
        if v2_doc is not None:
            return v2_doc, SchemaVersion.V2
        return await self._legacy_repo.find_by_id(code), SchemaVersion.V1

    # ── Private: gates and derived facts ──────────────────────────────────────

    @staticmethod
    def _password_matches(doc: _PublicDoc, is_v2: bool, password: str) -> bool:
        """v2 stores an argon2 hash; v1/emoji store plaintext."""
        if is_v2:
            return verify_password(password, doc.password)
        return password == doc.password

    def _effective_status(self, doc: _PublicDoc, is_v2: bool, now: datetime) -> str:
        """Derive the wire status (lowercase) — READ-ONLY, no writes.

        The persisted EXPIRED flip happens on the click path; this endpoint
        must never report "active" for a link the redirect would refuse.
        """
        if is_v2:
            if doc.status == UrlStatus.ACTIVE and self._expiry_reached(
                doc.expire_after, doc.max_clicks, doc.total_clicks, now
            ):
                return "expired"
            return doc.status.value.lower()
        # v1/emoji docs have no status field — mirror the legacy stats
        # page's inline rule: expiration-time passed or max-clicks reached.
        if self._expiry_reached(
            doc.expiration_time, doc.max_clicks, doc.total_clicks, now
        ):
            return "expired"
        return "active"

    @staticmethod
    def _expiry_reached(
        expire_at: datetime | None,
        max_clicks: int | None,
        total_clicks: int,
        now: datetime,
    ) -> bool:
        if max_clicks is not None and total_clicks >= max_clicks:
            return True
        expire_at = _as_utc(expire_at)
        return expire_at is not None and expire_at <= now

    def _link_facts(
        self,
        doc: _PublicDoc,
        alias: str,
        status: str,
        *,
        is_v2: bool,
        is_owner: bool,
    ) -> dict[str, Any]:
        long_url = doc.long_url if is_v2 else doc.url
        return {
            "alias": alias,
            "short_url": f"https://{self._system_default_domain}/{alias}",
            # Destination-only-while-active, like the preview page: an
            # expired, paused, or blocked link's stats page must not out
            # the destination. Owner sessions always get it.
            "long_url": long_url if (status == "active" or is_owner) else None,
            # v1/emoji docs never stored a creation timestamp.
            "created_at": _as_utc(doc.created_at) if is_v2 else None,
            "status": status,
            "max_clicks": doc.max_clicks,
            "block_bots": bool(doc.block_bots),
            "password_protected": bool(doc.password),
        }

    # ── Private: date window ──────────────────────────────────────────────────

    def _resolve_window(
        self,
        start_raw: str | None,
        end_raw: str | None,
        tz_name: str,
    ) -> tuple[datetime, datetime, str]:
        """Defaults and validation mirroring StatsService.query."""
        start = parse_datetime(start_raw) if start_raw else None
        if start_raw and start is None:
            raise ValidationError("invalid start_date format")
        end = parse_datetime(end_raw) if end_raw else None
        if end_raw and end is None:
            raise ValidationError("invalid end_date format")

        now = datetime.now(timezone.utc)
        if start is None and end is None:
            end = now
            start = now - timedelta(days=7)
        elif start is None:
            start = end - timedelta(days=7)
        elif end is None:
            end = now

        if start > now:
            start = now
        if end > now:
            end = now

        if start > end:
            raise ValidationError("start_date must be before end_date")
        if (end - start).days > self._max_date_range_days:
            raise ValidationError(
                f"date range cannot exceed {self._max_date_range_days} days"
            )

        tz_name = _TIMEZONE_ALIASES.get(tz_name, tz_name)
        if tz_name not in available_timezones():
            log.info("invalid_timezone_provided", timezone=tz_name, fallback="UTC")
            tz_name = "UTC"

        return start, end, tz_name

    # ── Private: v2 stats (StatsService reuse, scoped by url_id) ─────────────

    async def _query_v2_stats(
        self,
        doc: UrlV2Doc,
        start_date: datetime,
        end_date: datetime,
        tz_name: str,
    ) -> dict[str, Any]:
        """Run the standard $facet aggregation scoped by ``meta.url_id``.

        Matching on url_id — never meta.short_code — so a same-alias link
        on a custom domain can never bleed into the public page.
        """
        click_query: dict[str, Any] = {
            "meta.url_id": doc.id,
            "clicked_at": {"$gte": start_date, "$lte": end_date},
        }
        summary, aggregation_results = await self._stats._execute_all_stats(
            click_query, _V2_GROUP_BY, start_date, end_date, tz_name
        )
        response = self._stats._format_results(
            StatsScope.ANON,
            doc.alias,
            start_date,
            end_date,
            {},
            _V2_GROUP_BY,
            _METRICS,
            tz_name,
            aggregation_results,
        )
        response["summary"] = summary
        return self._stats._add_metadata(response)

    # ── Private: v1/emoji stats (synthesized from the embedded doc) ──────────

    def _synthesize_v1_stats(
        self,
        doc: LegacyUrlDoc | EmojiUrlDoc,
        alias: str,
        start_date: datetime,
        end_date: datetime,
        tz_name: str,
    ) -> dict[str, Any]:
        """Build the SAME wire shape from v1's embedded counters.

        Dimension maps are lifetime totals (v1 never stored per-click
        events); only the daily counter time series can honour the window.
        """
        metrics: dict[str, list[dict[str, Any]]] = {}

        # counter keys are UTC day strings written by the click handler.
        start_day = start_date.astimezone(timezone.utc).date().isoformat()
        end_day = end_date.astimezone(timezone.utc).date().isoformat()
        metrics["clicks_by_time"] = [
            {"time": day, "clicks": int(count or 0)}
            for day, count in sorted((doc.counter or {}).items())
            if start_day <= day <= end_day
        ]
        metrics["unique_clicks_by_time"] = [
            {"time": day, "unique_clicks": int(count or 0)}
            for day, count in sorted((doc.unique_counter or {}).items())
            if start_day <= day <= end_day
        ]

        dimensions: list[tuple[str, dict[str, Any], Any]] = [
            ("browser", doc.browser, None),
            # v1 stores the field as os_name; the wire key is "os".
            ("os", doc.os_name, None),
            # v1 stores display names (dots→spaces) — convert to ISO
            # alpha-2 so flags render like v2 ("XX" fallback).
            ("country", doc.country, convert_country_name),
            ("referrer", doc.referrer, None),
        ]
        for key, source, transform in dimensions:
            clicks_rows, unique_rows = self._v1_dimension_rows(source, key, transform)
            metrics[f"clicks_by_{key}"] = clicks_rows
            metrics[f"unique_clicks_by_{key}"] = unique_rows

        # v1 tracks named-bot hits on the doc (no unique variant);
        # v2 never emits this dimension.
        metrics["clicks_by_bots"] = [
            {"bots": name, "clicks": int(count or 0)}
            for name, count in sorted(
                (doc.bots or {}).items(), key=lambda item: item[1], reverse=True
            )
        ]

        last_click = None
        if doc.last_click:
            try:
                last_click = datetime.strptime(
                    doc.last_click, _V1_LAST_CLICK_FORMAT
                ).replace(tzinfo=timezone.utc)
            except ValueError:
                last_click = None

        summary: dict[str, Any] = {
            # Lifetime totals — matching the dimension maps.
            "total_clicks": doc.total_clicks,
            "unique_clicks": len(doc.ips or []),
            "first_click": None,  # not stored on v1 docs
            "last_click": self._stats._to_user_tz(last_click, tz_name),
            "avg_redirection_time": round(doc.average_redirection_time or 0, 2),
        }

        response: dict[str, Any] = {
            "scope": StatsScope.ANON,
            "filters": {},
            "group_by": list(_V1_GROUP_BY),
            "timezone": tz_name,
            "short_code": alias,
            "time_range": {
                "start_date": self._stats._to_user_tz(start_date, tz_name),
                "end_date": self._stats._to_user_tz(end_date, tz_name),
            },
            # The frontend adapter picks bucket size and zero-fills from
            # this — v1 counters are daily, full stop.
            "time_bucket_info": {
                "strategy": "daily",
                "interval_minutes": 1440,
                "display_format": "%Y-%m-%d",
                "mongo_format": "%Y-%m-%d",
                "timezone": tz_name,
            },
            "metrics": metrics,
            "summary": summary,
        }
        return self._stats._add_metadata(response)

    @staticmethod
    def _v1_dimension_rows(
        source: dict[str, Any] | None,
        key: str,
        transform: Any = None,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """Turn a v1 ``{value: {"counts": n, "ips": [...]}}`` map into wire rows.

        Returns (clicks_rows, unique_rows) sorted by clicks descending —
        unique rows ride the same order so the frontend zip keeps the
        backend's ranking. Values that transform to the same output (e.g.
        two spellings hitting the "XX" country fallback) are merged.
        """
        clicks: dict[str, int] = {}
        unique_ips: dict[str, set[str]] = {}
        for raw_value, entry in (source or {}).items():
            if isinstance(entry, dict):
                count = int(entry.get("counts", 0) or 0)
                ips = entry.get("ips") or []
            else:  # defensively tolerate bare counters in legacy data
                count = int(entry or 0)
                ips = []
            value = transform(raw_value) if transform else raw_value
            clicks[value] = clicks.get(value, 0) + count
            unique_ips.setdefault(value, set()).update(ips)

        ordered = sorted(clicks, key=lambda value: clicks[value], reverse=True)
        clicks_rows = [{key: value, "clicks": clicks[value]} for value in ordered]
        unique_rows = [
            {key: value, "unique_clicks": len(unique_ips[value])} for value in ordered
        ]
        return clicks_rows, unique_rows
