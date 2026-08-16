"""
Request DTOs for statistics and export endpoints.

StatsQuery       — GET /api/v1/stats               (query parameters)
ExportQuery      — GET /api/v1/export              (superset: adds ``format``)
LinkStatsQuery   — GET /api/v1/stats/links/{id}    (no link-identity params)
LinkExportQuery  — GET /api/v1/export/links/{id}   (superset: adds ``format``)

All models parse comma-separated strings for multi-value fields and validate
IANA timezone names.  The JSON ``filters`` string is parsed into a typed dict.
The per-link variants drop ``scope``/``short_code``/``url_id`` entirely —
the path already names the link, so slicing or bucketing by link identity
is meaningless there.
"""

from __future__ import annotations

import json
from typing import Any, ClassVar, Literal

from bson import ObjectId
from pydantic import (
    Field,
    PrivateAttr,
    field_validator,
    model_validator,
)

from schemas.dto.base import RequestBase
from schemas.dto.requests._descriptions import (
    LINK_STATS_FILTERS_DESC,
    LINK_STATS_GROUP_BY_DESC,
    STATS_BROWSER_DESC,
    STATS_CITY_DESC,
    STATS_COUNTRY_DESC,
    STATS_DEVICE_DESC,
    STATS_END_DATE_DESC,
    STATS_FILTERS_DESC,
    STATS_GROUP_BY_DESC,
    STATS_METRICS_DESC,
    STATS_OS_DESC,
    STATS_REFERRER_DESC,
    STATS_SCOPE_DESC,
    STATS_SHORT_CODE_DESC,
    STATS_START_DATE_DESC,
    STATS_TIMEZONE_DESC,
    STATS_URL_ID_DESC,
    STATS_UTM_DESC,
)
from schemas.enums.stats import (
    ALLOWED_EXPORT_FORMATS,
    ALLOWED_FILTERS,
    ALLOWED_GROUP_BY,
    ALLOWED_METRICS,
    LINK_ALLOWED_FILTERS,
    LINK_ALLOWED_GROUP_BY,
    ExportFormat,
    StatsDimension,
    StatsScope,
)


def _parse_comma_separated(value: Any) -> list[str]:
    """Split a comma-separated string or pass-through a list."""
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item).strip() for item in value]
    return [item.strip() for item in str(value).split(",") if item.strip()]


class _StatsQueryBase(RequestBase):
    """Shared query surface for the stats/export family.

    Date window, grouping, metrics, timezone, and the dimension filters —
    everything except link-identity selection, which each endpoint adds
    (or deliberately omits) on top.
    """

    # Allowed-value sets are class-level so the per-link variants can
    # shrink them without touching the parsing logic.
    _ALLOWED_GROUP_BY: ClassVar[frozenset] = ALLOWED_GROUP_BY
    _ALLOWED_FILTERS: ClassVar[frozenset] = ALLOWED_FILTERS

    start_date: str | None = Field(
        default=None,
        max_length=50,
        description=STATS_START_DATE_DESC,
        examples=["2025-01-01T00:00:00Z"],
    )
    end_date: str | None = Field(
        default=None,
        max_length=50,
        description=STATS_END_DATE_DESC,
        examples=["2025-12-31T23:59:59Z"],
    )

    group_by: str | None = Field(
        default=None,
        max_length=200,
        description=STATS_GROUP_BY_DESC,
        examples=["time,browser", "country", "time,country,browser"],
    )
    metrics: str | None = Field(
        default=None,
        max_length=200,
        description=STATS_METRICS_DESC,
        examples=["clicks,unique_clicks", "clicks"],
    )

    timezone: str = Field(
        default="UTC",
        max_length=50,
        description=STATS_TIMEZONE_DESC,
        examples=["UTC", "America/New_York"],
    )

    filters: str | None = Field(
        default=None,
        max_length=5000,
        description=STATS_FILTERS_DESC,
        examples=[
            '{"browser":["Chrome","Firefox"]}',
            '{"country":["United States","Canada"],"browser":["Chrome"]}',
        ],
    )
    browser: str | None = Field(
        default=None,
        max_length=500,
        description=STATS_BROWSER_DESC,
        examples=["Chrome,Firefox"],
    )
    os: str | None = Field(
        default=None,
        max_length=500,
        description=STATS_OS_DESC,
        examples=["Windows,macOS"],
    )
    device: str | None = Field(
        default=None,
        max_length=200,
        description=STATS_DEVICE_DESC,
        examples=["mobile,desktop"],
    )
    country: str | None = Field(
        default=None,
        max_length=1000,
        description=STATS_COUNTRY_DESC,
        examples=["United States,Germany"],
    )
    city: str | None = Field(
        default=None,
        max_length=1000,
        description=STATS_CITY_DESC,
        examples=["San Francisco,Berlin"],
    )
    referrer: str | None = Field(
        default=None,
        max_length=2000,
        description=STATS_REFERRER_DESC,
        examples=["https://google.com,https://twitter.com"],
    )
    utm_source: str | None = Field(
        default=None,
        max_length=1000,
        description=STATS_UTM_DESC,
        examples=["newsletter,twitter"],
    )
    utm_medium: str | None = Field(
        default=None,
        max_length=1000,
        description=STATS_UTM_DESC,
        examples=["email,social"],
    )
    utm_campaign: str | None = Field(
        default=None,
        max_length=1000,
        description=STATS_UTM_DESC,
        examples=["summer-launch"],
    )

    # --- Parsed/validated results (private — not exposed as query params) ---
    _parsed_group_by: list[str] = PrivateAttr(default_factory=list)
    _parsed_metrics: list[str] = PrivateAttr(default_factory=list)
    _parsed_filters: dict[str, list[str]] = PrivateAttr(default_factory=dict)

    @property
    def parsed_group_by(self) -> list[str]:
        return self._parsed_group_by

    @property
    def parsed_metrics(self) -> list[str]:
        return self._parsed_metrics

    @property
    def parsed_filters(self) -> dict[str, list[str]]:
        return self._parsed_filters

    @model_validator(mode="after")
    def _parse_multi_value_fields(self) -> _StatsQueryBase:
        # group_by
        raw_group = _parse_comma_separated(self.group_by)
        invalid = set(raw_group) - self._ALLOWED_GROUP_BY
        if invalid:
            raise ValueError(f"invalid group_by values: {', '.join(invalid)}")
        self._parsed_group_by = raw_group if raw_group else ["time"]

        # metrics
        raw_metrics = _parse_comma_separated(self.metrics)
        if raw_metrics:
            invalid_m = set(raw_metrics) - ALLOWED_METRICS
            if invalid_m:
                raise ValueError(f"invalid metrics: {', '.join(invalid_m)}")
            self._parsed_metrics = raw_metrics
        else:
            self._parsed_metrics = ["clicks", "unique_clicks"]

        # filters JSON string
        parsed_filters: dict[str, list[str]] = {}
        if self.filters:
            try:
                filters_json = json.loads(self.filters)
            except json.JSONDecodeError as exc:
                raise ValueError("filters must be valid JSON") from exc
            if isinstance(filters_json, dict):
                for key, value in filters_json.items():
                    if key in self._ALLOWED_FILTERS:
                        parsed_filters[key] = _parse_comma_separated(value)

        # Individual dimension filter params
        for dim in (
            "browser",
            "os",
            "device",
            "country",
            "city",
            "referrer",
            "utm_source",
            "utm_medium",
            "utm_campaign",
        ):
            raw = getattr(self, dim, None)
            if raw:
                parsed_filters[dim] = _parse_comma_separated(raw)

        self._apply_identity_filters(parsed_filters)
        self._parsed_filters = parsed_filters

        return self

    def _apply_identity_filters(self, parsed_filters: dict[str, list[str]]) -> None:
        """Hook for link-identity filter params — none on the base."""


class StatsQuery(_StatsQueryBase):
    """Query parameters for GET /api/v1/stats.

    Multi-value parameters (``group_by``, ``metrics``, ``browser``, ``os``,
    ``country``, ``city``, ``referrer``) accept comma-separated strings.
    The ``filters`` parameter accepts a JSON object string.
    """

    scope: Literal[StatsScope.ALL, StatsScope.ANON] = Field(
        default=StatsScope.ALL, description=STATS_SCOPE_DESC
    )
    short_code: str | None = Field(
        default=None,
        max_length=50,
        description=STATS_SHORT_CODE_DESC,
        examples=["mylink"],
    )
    url_id: str | None = Field(
        default=None,
        max_length=1000,
        description=STATS_URL_ID_DESC,
        examples=["686cbf34cc37ed6bbcd82ab9"],
    )

    @field_validator("scope", mode="before")
    @classmethod
    def _normalize_scope(cls, v: str) -> str:
        return v.strip().lower() if isinstance(v, str) else v

    def _apply_identity_filters(self, parsed_filters: dict[str, list[str]]) -> None:
        # short_code filter is blocked when scope=anon (bypass prevention)
        if self.short_code and self.scope != StatsScope.ANON:
            parsed_filters["short_code"] = _parse_comma_separated(self.short_code)
        if self.url_id:
            parsed_filters["url_id"] = _parse_comma_separated(self.url_id)
        # anon queries have no owner arm — an id filter would re-scope the
        # alias lock onto anyone's link, so reject (param and JSON paths).
        if self.scope == StatsScope.ANON and parsed_filters.get(StatsDimension.URL_ID):
            raise ValueError("url_id filters require scope=all")
        # Format-validate every url_id value (the JSON filters path too) so
        # the service can convert to ObjectId without a second check. No
        # ownership check — the owner stamp already scopes the $match, so
        # foreign ids simply match nothing.
        invalid = [
            v
            for v in parsed_filters.get(StatsDimension.URL_ID, [])
            if not ObjectId.is_valid(v)
        ]
        if invalid:
            raise ValueError(f"invalid url_id filter values: {', '.join(invalid)}")


class LinkStatsQuery(_StatsQueryBase):
    """Query parameters for GET /api/v1/stats/links/{url_id}.

    StatsQuery minus link identity: no ``scope``, and no ``short_code`` or
    ``url_id`` params or filters — the path already selects the link.
    """

    _ALLOWED_GROUP_BY: ClassVar[frozenset] = LINK_ALLOWED_GROUP_BY
    _ALLOWED_FILTERS: ClassVar[frozenset] = LINK_ALLOWED_FILTERS

    group_by: str | None = Field(
        default=None,
        max_length=200,
        description=LINK_STATS_GROUP_BY_DESC,
        examples=["time,browser", "country", "time,country,browser"],
    )
    filters: str | None = Field(
        default=None,
        max_length=5000,
        description=LINK_STATS_FILTERS_DESC,
        examples=[
            '{"browser":["Chrome","Firefox"]}',
            '{"country":["United States","Canada"],"browser":["Chrome"]}',
        ],
    )


class _ExportFormatMixin(RequestBase):
    """Adds the required ``format`` field shared by both export DTOs."""

    format: Literal[
        ExportFormat.CSV, ExportFormat.XLSX, ExportFormat.JSON, ExportFormat.XML
    ] = Field(
        description="Export file format.",
    )

    @field_validator("format", mode="after")
    @classmethod
    def _validate_format(cls, v: str) -> str:
        v = v.strip().lower()
        if not v:
            raise ValueError("format parameter is required (csv, xlsx, json, xml)")
        if v not in ALLOWED_EXPORT_FORMATS:
            raise ValueError(
                f"invalid format — must be one of: {', '.join(ALLOWED_EXPORT_FORMATS)}"
            )
        return v


class ExportQuery(StatsQuery, _ExportFormatMixin):
    """Query parameters for GET /api/v1/export.

    Superset of StatsQuery — adds the required ``format`` parameter.
    """


class LinkExportQuery(LinkStatsQuery, _ExportFormatMixin):
    """Query parameters for GET /api/v1/export/links/{url_id}.

    Superset of LinkStatsQuery — adds the required ``format`` parameter.
    """
