"""
Stats domain enums and allowed-value sets.

These are domain concepts used by services, strategies, export formatters,
and DTOs.  Extracted from ``schemas.dto.requests.stats`` so that service-layer
code does not depend on a request DTO module.
"""

from __future__ import annotations

from enum import Enum


class StatsScope(str, Enum):
    """Stats query scope."""

    ALL = "all"
    ANON = "anon"


class StatsDimension(str, Enum):
    """Stats group-by and filter dimensions."""

    TIME = "time"
    BROWSER = "browser"
    OS = "os"
    DEVICE = "device"
    COUNTRY = "country"
    CITY = "city"
    REFERRER = "referrer"
    SHORT_CODE = "short_code"
    # Filter-only — never a group-by dimension (short_code already buckets
    # by link identity on the wire).
    URL_ID = "url_id"
    UTM_SOURCE = "utm_source"
    UTM_MEDIUM = "utm_medium"
    UTM_CAMPAIGN = "utm_campaign"


class StatsMetric(str, Enum):
    """Stats metric types."""

    CLICKS = "clicks"
    UNIQUE_CLICKS = "unique_clicks"


class ExportFormat(str, Enum):
    """Export file formats."""

    CSV = "csv"
    XLSX = "xlsx"
    JSON = "json"
    XML = "xml"


ALLOWED_SCOPES = frozenset(StatsScope)
ALLOWED_GROUP_BY = frozenset(StatsDimension) - {StatsDimension.URL_ID}
ALLOWED_METRICS = frozenset(StatsMetric)
ALLOWED_FILTERS = frozenset(
    {
        StatsDimension.BROWSER,
        StatsDimension.OS,
        StatsDimension.DEVICE,
        StatsDimension.COUNTRY,
        StatsDimension.CITY,
        StatsDimension.REFERRER,
        StatsDimension.SHORT_CODE,
        StatsDimension.URL_ID,
        StatsDimension.UTM_SOURCE,
        StatsDimension.UTM_MEDIUM,
        StatsDimension.UTM_CAMPAIGN,
    }
)
# Per-link endpoints pre-select the link in the path, so slicing or
# bucketing by link identity is meaningless there.
LINK_ALLOWED_GROUP_BY = ALLOWED_GROUP_BY - {StatsDimension.SHORT_CODE}
LINK_ALLOWED_FILTERS = ALLOWED_FILTERS - {
    StatsDimension.SHORT_CODE,
    StatsDimension.URL_ID,
}
ALLOWED_EXPORT_FORMATS = frozenset(ExportFormat)
