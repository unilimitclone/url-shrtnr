"""
Public link preview service — GET /api/v1/public/preview/{short_code}.

Resolves a short code across both URL generations WITHOUT status gating
(expired / inactive / blocked links still answer; only truly missing codes
404) and derives the preview wire shape. The safety semantic the page is
built on: the destination (and geo rules) ride the wire ONLY while the
link is active and not password-protected — the preview never reveals a
destination the redirect would refuse to serve. For geo-targeted links
that means enumerating the full country→destination map while a single
redirect follows only one rule: deliberate anti-cloaking transparency,
not a leak.

Deliberately does NOT use ``UrlService.resolve`` — it raises on non-active
statuses and its cache shape lacks ``created_at``. Raw docs are resolved
here instead, in the order ``shared.alias_dispatch.resolution_order``
prescribes (the same single source of truth the redirect dispatches on).
Lookups are scoped to the system default domain: custom-domain aliases
resolve only via the redirect; this endpoint is system-domain-only.

Everything is derived READ-ONLY — this endpoint never writes.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from urllib.parse import unquote

from errors import NotFoundError
from infrastructure.logging import get_logger
from repositories.legacy.emoji_url_repository import EmojiUrlRepository
from repositories.legacy.legacy_url_repository import LegacyUrlRepository
from repositories.url_repository import UrlRepository
from schemas.dto.responses.public_preview import (
    PreviewDestination,
    PreviewGeoDestination,
    PublicPreviewResponse,
)
from schemas.models.url import SchemaVersion, UrlStatus, UrlV2Doc
from shared.alias_dispatch import resolution_order
from shared.datetime_utils import convert_to_gmt, parse_datetime
from shared.url_utils import split_destination

log = get_logger(__name__)


class PublicPreviewService:
    """Resolution + derivation for the public link preview wire."""

    def __init__(
        self,
        url_repo: UrlRepository,
        legacy_repo: LegacyUrlRepository,
        emoji_repo: EmojiUrlRepository,
        *,
        system_default_domain: str,
    ) -> None:
        self._url_repo = url_repo
        self._legacy_repo = legacy_repo
        self._emoji_repo = emoji_repo
        self._system_default_domain = system_default_domain

    # ── Public API ────────────────────────────────────────────────────────

    async def get_preview(self, short_code: str) -> PublicPreviewResponse:
        """Resolve *short_code* (status-agnostic) and build the preview.

        Generation lookup order comes from ``resolution_order`` — shared
        with the redirect so both surfaces always answer a given code from
        the same generation. Lookups are exact matches; case is never
        normalized ("/Docs" and "/docs" are different links).

        Raises:
            NotFoundError: the code exists in neither generation.
        """
        # Emoji aliases arrive percent-encoded — same as the redirect path.
        short_code = unquote(short_code)

        for generation in resolution_order(short_code):
            if generation is SchemaVersion.V2:
                v2_doc = await self._url_repo.find_by_alias(
                    short_code, self._system_default_domain
                )
                if v2_doc is not None:
                    return self._v2_preview(v2_doc)
            else:
                repo = (
                    self._emoji_repo
                    if generation is SchemaVersion.EMOJI
                    else self._legacy_repo
                )
                v1_doc = await self._find_v1_raw(repo, short_code)
                if v1_doc is not None:
                    return self._v1_preview(short_code, v1_doc)

        log.info("public_preview_not_found", short_code=short_code)
        raise NotFoundError("short_code not found")

    # ── Resolution helpers ────────────────────────────────────────────────

    @staticmethod
    async def _find_v1_raw(
        repo: LegacyUrlRepository | EmojiUrlRepository, short_code: str
    ) -> dict | None:
        """Fetch a v1/emoji document as a RAW dict by exact ``_id`` match.

        Not ``find_by_id``: that returns a typed ``LegacyUrlDoc``, which
        silently drops ``creation-date`` / ``creation-time`` (the model
        doesn't declare them and pydantic ignores extras) — and the preview
        needs them for ``created_at``. The public ``aggregate`` helper is
        how the legacy stats page reads raw v1 docs too.
        """
        return await repo.aggregate([{"$match": {"_id": short_code}}])

    # ── v2 derivation ─────────────────────────────────────────────────────

    def _v2_preview(self, doc: UrlV2Doc) -> PublicPreviewResponse:
        status = self._v2_effective_status(doc)
        password_protected = bool(doc.password)

        # Destination-only-while-active: password, expiry, pause and block
        # all withhold it (time-sensitive links stay dead, blocked
        # destinations stay unreachable). There is no password unlock here.
        destination: PreviewDestination | None = None
        geo_destinations: list[PreviewGeoDestination] | None = None
        if status == "active" and not password_protected:
            destination = PreviewDestination(**split_destination(doc.long_url))
            geo_destinations = self._group_geo_rules(doc.geo_rules)

        created_at = parse_datetime(doc.created_at)
        return PublicPreviewResponse(
            generation="v2",
            alias=doc.alias,
            short_url=f"https://{self._system_default_domain}/{doc.alias}",
            status=status,
            created_at=created_at.isoformat() if created_at else None,
            password_protected=password_protected,
            destination=destination,
            geo_destinations=geo_destinations,
        )

    def _v2_effective_status(self, doc: UrlV2Doc) -> str:
        """Lowercase wire status, folding derived expiry into ``expired``.

        The persisted status flip happens on the click path
        (``UrlRepository.expire_if_max_clicks``); a time-based flip has no
        writer at all — the redirect never compares ``expire_after`` to
        now. The invariant this endpoint holds is one-directional: the
        preview never reveals a destination the redirect would refuse.
        Deriving time-based expiry here is therefore DELIBERATELY STRICTER
        than the expiry-blind redirect (a lapsed-but-still-ACTIVE link
        reads ``expired`` and withholds its destination even though the
        redirect would still serve it). Do not "fix" that divergence by
        deleting the check — it errs in the safe direction. Derived here,
        never written back.
        """
        if doc.status == UrlStatus.ACTIVE:
            expire_after = self._as_aware_utc(doc.expire_after)
            if expire_after is not None and expire_after <= datetime.now(timezone.utc):
                return "expired"
            if doc.max_clicks is not None and doc.total_clicks >= doc.max_clicks:
                return "expired"
        return doc.status.value.lower()

    @staticmethod
    def _group_geo_rules(
        geo_rules: dict[str, str] | None,
    ) -> list[PreviewGeoDestination] | None:
        """Group geo rules by destination URL, countries sorted ascending.

        Anti-cloaking rule: EVERY rule is listed, nothing summarized —
        the preview is the transparency surface. Same display grouping as
        the legacy Jinja preview (storage stays a flat code→url map).
        """
        if not geo_rules:
            return None
        grouped: dict[str, list[str]] = {}
        for country, dest in geo_rules.items():
            grouped.setdefault(dest, []).append(country)
        return [
            PreviewGeoDestination(countries=sorted(codes), **split_destination(dest))
            for dest, codes in grouped.items()
        ]

    # ── v1 / emoji derivation ─────────────────────────────────────────────

    def _v1_preview(self, alias: str, data: dict) -> PublicPreviewResponse:
        # v1 has no status field and can never be inactive or blocked.
        status = "expired" if self._v1_is_expired(data) else "active"
        password_protected = bool(data.get("password"))

        destination: PreviewDestination | None = None
        if status == "active" and not password_protected:
            destination = PreviewDestination(**split_destination(data.get("url") or ""))

        return PublicPreviewResponse(
            generation="v1",
            alias=alias,
            short_url=f"https://{self._system_default_domain}/{alias}",
            status=status,
            created_at=self._v1_created_at(data),
            password_protected=password_protected,
            destination=destination,
            geo_destinations=None,  # geo targeting is v2-only
        )

    @staticmethod
    def _v1_is_expired(data: dict) -> bool:
        """Mirror the legacy stats page's expired logic (routes/legacy/
        stats.py): max-clicks reached or ``expiration-time`` passed.

        Like ``convert_to_gmt``, a timezone-naive expiration is ambiguous
        and never counts as expired; unparseable ancient values are
        treated the same rather than 500-ing a public page.
        """
        max_clicks = data.get("max-clicks")
        if max_clicks is not None:
            try:
                if int(data.get("total-clicks") or 0) >= int(max_clicks):
                    return True
            except (TypeError, ValueError):
                pass

        raw_expiration = data.get("expiration-time")
        if raw_expiration is None:
            return False
        if isinstance(raw_expiration, datetime):
            expires_at = raw_expiration if raw_expiration.tzinfo else None
        else:
            try:
                expires_at = convert_to_gmt(str(raw_expiration))
            except (TypeError, ValueError):
                expires_at = None
        return expires_at is not None and expires_at.astimezone(
            timezone.utc
        ) <= datetime.now(timezone.utc)

    @staticmethod
    def _v1_created_at(data: dict) -> str | None:
        """Combine v1 ``creation-date`` + ``creation-time`` (both set at
        shorten time) into an ISO string; either missing or unparseable →
        ``None`` — ancient rows lack them and the frontend omits the line.
        """
        date = data.get("creation-date")
        time = data.get("creation-time")
        if not date or not time:
            return None
        created_at = parse_datetime(f"{date}T{time}")
        return created_at.isoformat() if created_at else None

    # ── Shared helpers ────────────────────────────────────────────────────

    @staticmethod
    def _as_aware_utc(dt: Any) -> datetime | None:
        """Normalize a stored datetime for comparison — Mongo returns naive
        UTC datetimes by default (the client is not ``tz_aware``)."""
        if not isinstance(dt, datetime):
            return None
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
