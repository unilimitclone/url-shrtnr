"""
URL resolution, creation, update, deletion, and listing service.

Extracts business logic from:
  - blueprints/redirector.py  (resolve + dispatch heuristic)
  - builders/create.py        (create)
  - builders/update.py        (update)
  - builders/query.py         (list_by_owner)

Dispatch heuristic (get_url_by_length_and_type) is preserved exactly:
  emoji alias  → emojis collection, schema "emoji"
  7 chars      → urlsV2 first, urls fallback
  6 chars      → urls first, urlsV2 fallback
  other        → urlsV2 first, urls fallback
"""

from __future__ import annotations

import re
import time
from collections.abc import Awaitable, Callable
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Literal

from bson import ObjectId

from errors import (
    AppError,
    BlockedUrlError,
    ConflictError,
    ForbiddenError,
    GoneError,
    NotFoundError,
    ValidationError,
)
from infrastructure.cache.url_cache import UrlCache, UrlCacheData
from infrastructure.crypto import hash_password
from infrastructure.logging import get_logger, should_sample
from repositories.blocked_url_repository import BlockedUrlRepository
from repositories.legacy.emoji_url_repository import EmojiUrlRepository
from repositories.legacy.legacy_url_repository import LegacyUrlRepository
from repositories.url_repository import UrlRepository
from schemas.dto.requests.url import (
    CreateUrlRequest,
    ListUrlsQuery,
    MetaTagsRequest,
    UpdateUrlRequest,
)
from services.edge_cache.og_writethrough import OgEdgeWritethrough
from services.meta_tags.events import MetaImageValidateEvent
from services.meta_tags.images import ingest_meta_image

if TYPE_CHECKING:
    from infrastructure.storage.r2 import R2StorageClient
    from services.meta_tags.sinks import MetaImageValidationSink
from schemas.models.base import ANONYMOUS_OWNER_ID
from schemas.models.url import (
    EmojiUrlDoc,
    LegacyUrlDoc,
    LinkMetaTags,
    SchemaVersion,
    UrlStatus,
    UrlV2Doc,
)
from shared.datetime_utils import parse_datetime
from shared.generators import generate_short_code_v2
from shared.url_utils import extract_hostname
from shared.validators import (
    is_emoji_alias,
    validate_alias,
    validate_blocked_url,
    validate_emoji_alias,
    validate_url,
)

log = get_logger(__name__)

AliasCheckResult = Literal["available", "length", "format", "taken"]

# ── Field update handlers ────────────────────────────────────────────────────
#
# Each handler inspects one field on the update request and, if changed,
# writes the new value into `ops`.  Handlers are registered in
# FIELD_HANDLERS and iterated by UrlService.update().
#
# Signature: (request, existing, ops, service) -> None
#   request  — UpdateUrlRequest from the caller
#   existing — current UrlV2Doc from the database
#   ops      — dict collecting $set fields (mutated in place)
#   service  — the UrlService instance (for cross-cutting helpers)


async def _handle_long_url(
    request: UpdateUrlRequest, existing: UrlV2Doc, ops: dict, service: UrlService
) -> None:
    if request.long_url is not None and request.long_url != existing.long_url:
        if not validate_url(
            request.long_url, blocked_self_domains=service._blocked_self_domains
        ):
            raise ValidationError("URL is not allowed or invalid", field="long_url")
        ops["long_url"] = request.long_url


async def _handle_alias(
    request: UpdateUrlRequest, existing: UrlV2Doc, ops: dict, service: UrlService
) -> None:
    if request.alias is not None and request.alias != existing.alias:
        # Scope the collision check to wherever the URL will land. If the same
        # request is also moving the URL to a different domain, we must verify
        # the new alias is free on the *target* tenant — not the current one.
        scope = (
            (request.domain or service._system_default_domain)
            if "domain" in request.model_fields_set
            else existing.domain
        )
        if not await service.check_alias_available(request.alias, domain=scope):
            log.info(
                "url_alias_conflict",
                short_code=request.alias,
                domain=scope,
            )
            raise ConflictError("Alias is already in use")
        ops["alias"] = request.alias


async def _handle_domain(
    request: UpdateUrlRequest, existing: UrlV2Doc, ops: dict, service: UrlService
) -> None:
    """Move a URL to a different domain namespace.

    Route layer is responsible for verifying the caller owns the target as an
    ACTIVE custom domain (or that it's the system default). Service treats the
    value as opaque.
    """
    if "domain" not in request.model_fields_set:
        return
    target = request.domain or service._system_default_domain
    if target == existing.domain:
        return
    # If alias isn't also changing, verify the existing alias is free on the
    # target tenant. The alias handler already ran (it's listed first in
    # FIELD_HANDLERS) and validated its own collision against `target`, so we
    # only need to check when alias is staying put.
    if "alias" not in ops and not await service.check_alias_available(
        existing.alias, domain=target
    ):
        log.info(
            "url_domain_move_alias_conflict",
            short_code=existing.alias,
            from_domain=existing.domain,
            to_domain=target,
        )
        raise ConflictError(f"Alias '{existing.alias}' is already in use on {target}")
    ops["domain"] = target


async def _handle_password(
    request: UpdateUrlRequest, existing: UrlV2Doc, ops: dict, service: UrlService
) -> None:
    if "password" not in request.model_fields_set:
        return
    if not request.password and existing.password:
        # Empty string clears the password
        ops["password"] = None
    elif request.password:
        # Always re-hash — argon2 uses random salts so string comparison
        # cannot detect "same password", and the write is cheap.
        ops["password"] = hash_password(request.password)


async def _handle_max_clicks(
    request: UpdateUrlRequest, existing: UrlV2Doc, ops: dict, service: UrlService
) -> None:
    if "max_clicks" not in request.model_fields_set:
        return
    if (request.max_clicks is None or request.max_clicks == 0) and existing.max_clicks:
        ops["max_clicks"] = None
    elif request.max_clicks and request.max_clicks != existing.max_clicks:
        ops["max_clicks"] = request.max_clicks


async def _handle_expire_after(
    request: UpdateUrlRequest, existing: UrlV2Doc, ops: dict, service: UrlService
) -> None:
    if "expire_after" not in request.model_fields_set:
        return
    if request.expire_after is None and existing.expire_after:
        ops["expire_after"] = None
    elif request.expire_after is not None:
        if request.expire_after <= datetime.now(timezone.utc):
            raise ValidationError(
                "expire_after must be in the future", field="expire_after"
            )
        if request.expire_after != existing.expire_after:
            ops["expire_after"] = request.expire_after


async def _handle_status(
    request: UpdateUrlRequest, existing: UrlV2Doc, ops: dict, service: UrlService
) -> None:
    if request.status is not None and request.status != existing.status:
        ops["status"] = request.status


async def _handle_meta_tags(
    request: UpdateUrlRequest, existing: UrlV2Doc, ops: dict, service: UrlService
) -> None:
    if "meta_tags" not in request.model_fields_set:
        return
    if request.meta_tags is None:
        if existing.meta_tags:
            ops["meta_tags"] = None
        return
    # Resolve data-URI uploads first, then validate. Registered after
    # long_url so a same-request destination change is validated against
    # the NEW destination.
    meta_req, image_meta = await service.resolve_meta_image(
        request.meta_tags, existing.owner_id
    )
    await service.validate_meta_tags(
        meta_req, long_url=ops.get("long_url", existing.long_url)
    )
    ops["meta_tags"] = LinkMetaTags(
        title=meta_req.title,
        description=meta_req.description,
        image=meta_req.image,
        color=meta_req.color,
        image_meta=image_meta,
        updated_at=datetime.now(timezone.utc),
    ).model_dump()


def _simple_field_handler(field_name: str) -> Callable:
    """Factory for nullable fields that just need a changed-check."""

    async def handler(
        request: UpdateUrlRequest, existing: UrlV2Doc, ops: dict, service: UrlService
    ) -> None:
        if field_name not in request.model_fields_set:
            return
        value = getattr(request, field_name)
        current = getattr(existing, field_name)
        if value is None and current:
            ops[field_name] = None
        elif value != current:
            ops[field_name] = value

    return handler


FIELD_HANDLERS: dict[str, Callable[..., Awaitable[None]]] = {
    "long_url": _handle_long_url,
    "alias": _handle_alias,
    # `domain` must follow `alias` — the alias handler peeks at the incoming
    # domain to scope its collision check, and the domain handler peeks at
    # `ops` to decide whether the alias still needs verifying on the target.
    "domain": _handle_domain,
    "password": _handle_password,
    "max_clicks": _handle_max_clicks,
    "expire_after": _handle_expire_after,
    "block_bots": _simple_field_handler("block_bots"),
    "private_stats": _simple_field_handler("private_stats"),
    "status": _handle_status,
    # Must follow long_url — the handler validates against ops["long_url"]
    # when the destination changes in the same request.
    "meta_tags": _handle_meta_tags,
}


class UrlService:
    def __init__(
        self,
        url_repo: UrlRepository,
        legacy_repo: LegacyUrlRepository,
        emoji_repo: EmojiUrlRepository,
        blocked_url_repo: BlockedUrlRepository,
        url_cache: UrlCache,
        blocked_self_domains: list[str],
        system_default_domain: str,
        blocked_url_regex_timeout: float = 0.2,
        max_emoji_alias_length: int = 15,
        og_writethrough: OgEdgeWritethrough | None = None,
        r2_storage: R2StorageClient | None = None,
        meta_image_max_bytes: int = 512_000,
        meta_image_sink: MetaImageValidationSink | None = None,
    ) -> None:
        self._url_repo = url_repo
        self._legacy_repo = legacy_repo
        self._emoji_repo = emoji_repo
        self._blocked_url_repo = blocked_url_repo
        self._url_cache = url_cache
        self._blocked_self_domains = blocked_self_domains
        # The only domain on which v1/legacy lookups fire — custom domains
        # are v2-only by definition.
        self._system_default_domain = system_default_domain
        self._blocked_url_regex_timeout = blocked_url_regex_timeout
        self._max_emoji_alias_length = max_emoji_alias_length
        # Edge KV write-through for og-links; None when edge cache is
        # unconfigured (self-host) — origin then serves all previews.
        self._og_writethrough = og_writethrough
        # R2 upload target for data-URI og:images; None ⇒ uploads rejected,
        # https image URLs unaffected (self-host degradation).
        self._r2_storage = r2_storage
        self._meta_image_max_bytes = meta_image_max_bytes
        # Async validation for EXTERNAL https images (uploads are validated
        # synchronously). None ⇒ validation skipped (no queue Redis).
        self._meta_image_sink = meta_image_sink

    # ── Public API ────────────────────────────────────────────────────────────

    async def resolve(
        self, short_code: str, *, domain: str | None = None
    ) -> tuple[UrlCacheData, SchemaVersion]:
        """
        Resolve a short code to UrlCacheData and schema version.

        ``domain`` scopes the lookup to a custom tenant. None or the system
        default falls back to the original cross-collection path (v2 + v1
        + emoji). Custom tenants only resolve against urlsV2 — v1/emoji
        predate per-domain scoping and never live on custom hostnames.

        Returns (UrlCacheData, schema_version) where schema_version is
        a SchemaVersion enum member (V2, V1, or EMOJI).

        Raises:
            NotFoundError:   URL not found in any collection.
            BlockedUrlError: URL status is BLOCKED (v2 only).
            GoneError:       URL status is EXPIRED or INACTIVE (v2 only).
        """
        scope = domain or self._system_default_domain
        is_custom = scope != self._system_default_domain
        # 1. Cache hit
        cached = await self._url_cache.get(short_code, scope)
        if cached is not None:
            schema = cached.schema_version
            if schema == SchemaVersion.V2 and cached.url_status in (
                UrlStatus.BLOCKED,
                UrlStatus.EXPIRED,
                UrlStatus.INACTIVE,
            ):
                log.info(
                    "url_resolve_non_active",
                    short_code=short_code,
                    status=cached.url_status,
                    schema=schema,
                    source="cache",
                )
                _raise_for_status(cached.url_status)
            if should_sample("cache_operation"):
                log.debug(
                    "url_cache_hit",
                    short_code=short_code,
                    schema=schema,
                    status=cached.url_status,
                )
            return cached, schema

        # 2. Cache miss — dispatch by length and type
        if should_sample("cache_operation"):
            log.debug("url_cache_miss", short_code=short_code)
        if is_custom:
            url_cache_data, schema = await self._dispatch_custom_domain(
                short_code, scope
            )
        else:
            url_cache_data, schema = await self._dispatch(short_code)
        if url_cache_data is None:
            log.info("url_resolve_not_found", short_code=short_code, domain=scope)
            raise NotFoundError("URL not found")

        # 3. Populate cache according to caching rules
        await self._populate_cache(short_code, url_cache_data, schema)

        # 4a. Raise for non-ACTIVE v2 (after caching minimal data)
        if schema == SchemaVersion.V2 and url_cache_data.url_status in (
            UrlStatus.BLOCKED,
            UrlStatus.EXPIRED,
            UrlStatus.INACTIVE,
        ):
            log.info(
                "url_resolve_non_active",
                short_code=short_code,
                status=url_cache_data.url_status,
                schema=schema,
                source="db",
            )
            _raise_for_status(url_cache_data.url_status)

        # 4b. Raise for v1 URLs whose max-clicks have been exhausted
        if (
            schema == SchemaVersion.V1
            and url_cache_data.max_clicks is not None
            and url_cache_data.total_clicks >= url_cache_data.max_clicks
        ):
            log.info(
                "url_resolve_expired_max_clicks",
                short_code=short_code,
                total_clicks=url_cache_data.total_clicks,
                max_clicks=url_cache_data.max_clicks,
            )
            raise GoneError("URL has expired (max clicks reached)")

        return url_cache_data, schema

    async def check_alias_available(
        self, alias: str, *, domain: str | None = None
    ) -> bool:
        """Return True if alias is free under the given domain namespace.

        When ``domain`` is explicitly the system default (or omitted), also
        checks the legacy ``urls`` collection — v1 alias collisions still
        matter on the original namespace. Custom domains only check v2 since
        v1/emoji predate per-domain scoping and never live on custom
        hostnames.
        """
        target_domain = domain or self._system_default_domain
        if await self._url_repo.check_alias_exists(alias, target_domain):
            return False
        if target_domain == self._system_default_domain:
            return not await self._legacy_repo.check_exists(alias)
        return True

    async def check_alias(
        self, alias: str, *, domain: str | None = None
    ) -> AliasCheckResult:
        """Evaluate a candidate alias against the full creation rules.

        Mirrors what POST /api/v1/shorten would enforce (length, charset,
        collision) so the UI can surface precise feedback without duplicating
        the rules. Returns a single literal describing the first failing check,
        or ``"available"`` when the alias would be accepted today.
        """
        if not (3 <= len(alias) <= 16):
            return "length"
        if not validate_alias(alias):
            return "format"
        if not await self.check_alias_available(alias, domain=domain):
            return "taken"
        return "available"

    async def resolve_meta_image(
        self, meta: MetaTagsRequest, owner_id: ObjectId
    ) -> tuple[MetaTagsRequest, dict | None]:
        """Resolve a data-URI image to its R2-hosted URL.

        Returns the (possibly rewritten) request plus synchronous
        image_meta for uploads; https URLs pass through untouched (the
        async validator checks them out-of-band).
        """
        if not meta.image:
            return meta, None
        ingested = await ingest_meta_image(
            meta.image,
            owner_id=owner_id,
            storage=self._r2_storage,
            max_bytes=self._meta_image_max_bytes,
        )
        if ingested.r2_hosted:
            return meta.model_copy(update={"image": ingested.url}), ingested.image_meta
        return meta, None

    async def validate_meta_tags(self, meta: MetaTagsRequest, *, long_url: str) -> None:
        """Abuse checks for a meta_tags write.

        Blocklist regexes run over title/description/image (the same
        patterns the long_url flows through at create), plus a destination
        re-check — a link that was fine as a bare redirect deserves a second
        look the moment someone dresses it up with a custom preview.
        """
        patterns = await self._blocked_url_repo.get_patterns()
        for value in (meta.title, meta.description, meta.image):
            if value and not validate_blocked_url(
                value, patterns, timeout=self._blocked_url_regex_timeout
            ):
                log.info("meta_tags_rejected", reason="blocked_pattern")
                raise ValidationError(
                    "meta_tags content is not allowed", field="meta_tags"
                )
        if not validate_blocked_url(
            long_url, patterns, timeout=self._blocked_url_regex_timeout
        ):
            log.info("meta_tags_rejected", reason="blocked_destination")
            raise ValidationError("URL is blocked", field="long_url")

    async def create(
        self,
        request: CreateUrlRequest,
        owner_id: ObjectId | None,
        client_ip: str,
        *,
        domain: str | None = None,
    ) -> UrlV2Doc:
        """
        Create a new shortened URL.

        ``domain`` scopes the new URL to a tenant. None or omitted defaults to
        the system default. Callers MUST validate domain ownership + ACTIVE
        status before calling — service treats the value as opaque.

        Raises:
            ValidationError: URL is invalid, blocked, or field validation fails.
            ConflictError:   The requested alias is already taken.
        """
        target_domain = domain or self._system_default_domain
        now = datetime.now(timezone.utc)

        # 1. Validate the long URL (self-link check + format)
        if not validate_url(
            request.long_url, blocked_self_domains=self._blocked_self_domains
        ):
            log.info(
                "url_create_rejected",
                reason="invalid_url",
            )
            raise ValidationError("URL is not allowed or invalid", field="long_url")

        # 2. Check against DB blocked patterns
        # validate_blocked_url returns True if allowed, False if blocked
        blocked_patterns = await self._blocked_url_repo.get_patterns()
        if not validate_blocked_url(
            request.long_url, blocked_patterns, timeout=self._blocked_url_regex_timeout
        ):
            log.info(
                "url_create_rejected",
                reason="blocked_pattern",
            )
            raise ValidationError("URL is blocked", field="long_url")

        # 2b. Meta-tags: resolve data-URI uploads to R2 URLs, then abuse
        #     checks (route layer already gated the feature).
        meta_req = request.meta_tags
        meta_image_meta: dict | None = None
        if meta_req:
            meta_req, meta_image_meta = await self.resolve_meta_image(
                meta_req, owner_id if owner_id is not None else ANONYMOUS_OWNER_ID
            )
            await self.validate_meta_tags(meta_req, long_url=request.long_url)

        # 3. Password hash (cheap — do before alias generation loop)
        password_hash: str | None = None
        if request.password:
            password_hash = hash_password(request.password)

        # 4. expire_after (already parsed to datetime by the DTO validator)
        expire_ts: datetime | None = request.expire_after
        if expire_ts is not None and expire_ts <= now:
            raise ValidationError(
                "expire_after must be in the future", field="expire_after"
            )

        # 5. Alias — generate or validate custom (may loop; done after cheap checks)
        if request.alias:
            if not validate_alias(request.alias) and not validate_emoji_alias(
                request.alias, max_emojis=self._max_emoji_alias_length
            ):
                raise ValidationError(
                    "Alias contains invalid characters", field="alias"
                )
            if not await self.check_alias_available(
                request.alias, domain=target_domain
            ):
                log.info("url_alias_conflict", short_code=request.alias)
                raise ConflictError("Alias is already in use")
            alias = request.alias
        else:
            alias = await self._generate_unique_alias(domain=target_domain)

        # 6. private_stats default depends on auth state
        private_stats: bool | None = request.private_stats
        if private_stats is None:
            private_stats = True if owner_id is not None else None

        # 7. Build document model (validates fields via Pydantic)
        owner_oid = owner_id if owner_id is not None else ANONYMOUS_OWNER_ID
        url_doc = UrlV2Doc(
            alias=alias,
            owner_id=owner_oid,
            domain=target_domain,
            created_at=now,
            creation_ip=client_ip,
            long_url=request.long_url,
            password=password_hash,
            block_bots=request.block_bots,
            max_clicks=request.max_clicks,
            expire_after=expire_ts,
            status=UrlStatus.ACTIVE,
            private_stats=private_stats,
            total_clicks=0,
            last_click=None,
            meta_tags=(
                LinkMetaTags(
                    title=meta_req.title,
                    description=meta_req.description,
                    image=meta_req.image,
                    color=meta_req.color,
                    image_meta=meta_image_meta,
                    updated_at=now,
                    updated_ip=client_ip,
                )
                if meta_req
                else None
            ),
        )
        doc = url_doc.model_dump(by_alias=True, exclude={"id"})

        # 8. Insert
        inserted_id = await self._url_repo.insert(doc)
        url_doc.id = inserted_id

        _url_base = request.long_url.split("?")[0]
        _log_url = f"{_url_base}?[REDACTED]" if "?" in request.long_url else _url_base

        log.info(
            "url_created",
            short_code=alias,
            long_url=_log_url,
            long_url_domain=extract_hostname(request.long_url),
            user_id=str(owner_id) if owner_id else None,
            schema=SchemaVersion.V2,
            has_password=bool(password_hash),
            max_clicks=request.max_clicks,
            block_bots=request.block_bots,
            has_expiration=bool(expire_ts),
            private_stats=private_stats,
            alias_custom=bool(getattr(request, "alias", None)),
            domain=target_domain,
            has_meta_tags=bool(request.meta_tags),
        )

        # Edge-first: push the prerendered OG page to KV so preview bots
        # are answered at the edge. Best-effort — never fails the write.
        if url_doc.meta_tags and self._og_writethrough:
            await self._og_writethrough.sync(_v2_doc_to_cache(url_doc))

        # External https images get validated out-of-band (uploads carried
        # image_meta already). Best-effort emit — sink swallows failures.
        await self._maybe_emit_image_validation(url_doc)

        return url_doc

    async def update(
        self,
        url_id: ObjectId,
        request: UpdateUrlRequest,
        owner_id: ObjectId,
    ) -> UrlV2Doc:
        """
        Update an existing URL.

        EXPIRED URLs are auto-reactivated when expiry conditions change
        (max_clicks raised/cleared, expire_after extended/cleared), unless
        the caller also provides an explicit status override.

        Raises:
            NotFoundError:  URL doesn't exist.
            ForbiddenError: Caller doesn't own the URL, or URL is blocked.
            ConflictError:  Requested alias is already taken.
            ValidationError: Invalid field values.
        """
        now = datetime.now(timezone.utc)

        # 1. Load existing document
        existing = await self._url_repo.find_by_id(url_id)
        if existing is None:
            raise NotFoundError("URL not found")

        # 2. Ownership check
        if existing.owner_id != owner_id:
            raise ForbiddenError("Access denied: you do not own this URL")

        # 2b. Admin-blocked URLs cannot be modified by the owner
        if existing.status == UrlStatus.BLOCKED:
            raise ForbiddenError("Cannot modify a blocked URL")

        # 3. Build update ops via field handlers
        update_ops: dict = {}
        for handler in FIELD_HANDLERS.values():
            await handler(request, existing, update_ops, self)

        # Auto-reactivate EXPIRED URLs when expiry conditions improve
        self._auto_reactivate(existing, update_ops, now)

        if not update_ops:
            return existing  # No changes detected

        update_ops["updated_at"] = now

        # 4. Persist
        await self._url_repo.update(url_id, {"$set": update_ops})

        # 5. Invalidate cache. Always clear the pre-change (alias, domain) so a
        # rename or move can't be served stale from the old key. When the new
        # key differs (alias rename and/or domain move), clear that too —
        # belt-and-suspenders against a racing populate from another worker
        # that filled the cache between our read and persist.
        await self._url_cache.invalidate(existing.alias, existing.domain)
        new_alias = update_ops.get("alias", existing.alias)
        new_domain = update_ops.get("domain", existing.domain)
        if (new_alias, new_domain) != (existing.alias, existing.domain):
            await self._url_cache.invalidate(new_alias, new_domain)

        log.info(
            "url_updated",
            url_id=str(url_id),
            short_code=existing.alias,
            user_id=str(owner_id),
            fields_changed=list(update_ops.keys()),
        )
        if "domain" in update_ops:
            log.info(
                "url_domain_moved",
                url_id=str(url_id),
                short_code=new_alias,
                from_domain=existing.domain,
                to_domain=update_ops["domain"],
                user_id=str(owner_id),
            )

        # Return merged doc (avoids extra DB round-trip)
        merged = existing.model_dump(by_alias=True)
        merged.update(update_ops)
        merged["_id"] = url_id
        merged_doc = UrlV2Doc.from_mongo(merged)

        # Edge KV write-through — only for links that have meta_tags now or
        # had them before this write (plain links' promoted redirect entries
        # must never be touched). A key change (alias/domain move) drops the
        # old entry; sync() re-puts or deletes under the new key.
        if self._og_writethrough and (
            existing.meta_tags is not None or merged_doc.meta_tags is not None
        ):
            relevant = {"meta_tags", "long_url", "status", "alias", "domain"}
            if relevant & update_ops.keys():
                if (new_alias, new_domain) != (existing.alias, existing.domain):
                    await self._og_writethrough.remove(existing.domain, existing.alias)
                await self._og_writethrough.sync(_v2_doc_to_cache(merged_doc))

        if "meta_tags" in update_ops:
            await self._maybe_emit_image_validation(merged_doc)

        return merged_doc

    async def _maybe_emit_image_validation(self, doc: UrlV2Doc) -> None:
        """Queue async validation for an external https og:image."""
        meta = doc.meta_tags
        if (
            self._meta_image_sink is None
            or meta is None
            or not meta.image
            or meta.image_meta is not None  # upload — validated synchronously
        ):
            return
        await self._meta_image_sink.emit(
            MetaImageValidateEvent(
                url_id=str(doc.id),
                alias=doc.alias,
                domain=doc.domain,
                image_url=meta.image,
            )
        )

    def _auto_reactivate(
        self, existing: UrlV2Doc, update_ops: dict, now: datetime
    ) -> None:
        """Reactivate an EXPIRED URL if expiry conditions improve.

        Only applies when the URL is currently EXPIRED and the caller
        did not explicitly set a new status.
        """
        if existing.status != UrlStatus.EXPIRED:
            return
        if "status" in update_ops:
            return

        new_max = update_ops.get("max_clicks", existing.max_clicks)
        new_expire = update_ops.get("expire_after", existing.expire_after)

        max_clicks_cleared = "max_clicks" in update_ops and new_max is None
        max_clicks_raised = (
            new_max is not None
            and existing.max_clicks is not None
            and new_max > existing.total_clicks
        )
        expire_extended = new_expire is not None and new_expire > now
        expire_cleared = "expire_after" in update_ops and new_expire is None

        if max_clicks_cleared or max_clicks_raised or expire_extended or expire_cleared:
            update_ops["status"] = UrlStatus.ACTIVE

    async def delete(
        self,
        url_id: ObjectId,
        owner_id: ObjectId,
    ) -> None:
        """
        Delete a URL.

        Raises:
            NotFoundError:  URL doesn't exist.
            ForbiddenError: Caller doesn't own the URL, or URL is blocked.
        """
        existing = await self._url_repo.find_by_id(url_id)
        if existing is None:
            raise NotFoundError("URL not found")

        if existing.owner_id != owner_id:
            raise ForbiddenError("Access denied: you do not own this URL")

        if existing.status == UrlStatus.BLOCKED:
            raise ForbiddenError("Cannot delete a blocked URL")

        await self._url_repo.delete(url_id)
        await self._url_cache.invalidate(existing.alias, existing.domain)
        if existing.meta_tags is not None and self._og_writethrough:
            await self._og_writethrough.remove(existing.domain, existing.alias)

        log.info(
            "url_deleted",
            url_id=str(url_id),
            short_code=existing.alias,
            user_id=str(owner_id),
        )

    async def delete_all_by_domain(
        self,
        owner_id: ObjectId,
        domain: str,
    ) -> int:
        """Bulk-delete all URLs owned by *owner_id* under *domain*.

        Refuses the system default — that would nuke all of a user's spoo.me
        URLs in one call. Returns number of URLs deleted.

        Used by:
          - `DELETE /api/v1/urls?domain=` (standalone bulk delete)
          - `CustomDomainService.delete(cascade=True)` (domain revoke cascade)
        """
        if domain == self._system_default_domain:
            raise ValidationError(
                "cannot bulk-delete URLs on the system default domain",
                field="domain",
            )

        aliases = await self._url_repo.list_aliases_by_owner_and_domain(
            owner_id, domain
        )
        if not aliases:
            return 0

        deleted = await self._url_repo.delete_many_by_owner_and_domain(owner_id, domain)

        # Best-effort cache cleanup; cache miss after delete is correct anyway.
        await self._url_cache.invalidate_many(aliases, domain)

        log.info(
            "urls_bulk_deleted",
            user_id=str(owner_id),
            domain=domain,
            count=deleted,
        )
        return deleted

    async def list_by_owner(
        self,
        owner_id: ObjectId,
        query: ListUrlsQuery,
    ) -> dict:
        """Return a paginated list of URLs owned by this user.

        Returns a dict with ``items`` as a list of ``UrlV2Doc`` domain
        objects (not DTOs).  The route layer must map items to
        ``UrlListItem.from_doc()`` before returning to clients.
        """
        start_time = time.perf_counter()
        mongo_query: dict = {"owner_id": owner_id}

        if getattr(query, "domain", None):
            mongo_query["domain"] = query.domain

        f = query.parsed_filter

        if f:
            if f.status:
                mongo_query["status"] = f.status

            date_range: dict = {}
            if f.created_after:
                dt = parse_datetime(f.created_after)
                if dt:
                    date_range["$gte"] = dt
            if f.created_before:
                dt = parse_datetime(f.created_before)
                if dt:
                    date_range["$lte"] = dt
            if date_range:
                mongo_query["created_at"] = date_range

            if f.password_set is True:
                mongo_query["password"] = {"$ne": None}
            elif f.password_set is False:
                mongo_query["password"] = None

            if f.max_clicks_set is True:
                mongo_query["max_clicks"] = {"$ne": None}
            elif f.max_clicks_set is False:
                mongo_query["max_clicks"] = None

            if f.search:
                try:
                    pattern = re.compile(re.escape(f.search), re.IGNORECASE)
                    mongo_query["$or"] = [{"alias": pattern}, {"long_url": pattern}]
                except re.error:
                    raise ValidationError(
                        "Invalid search pattern", field="filter.search"
                    ) from None

        sort_order = (
            -1 if query.sort_order.lower() in ("desc", "descending", "-1") else 1
        )
        skip = (query.page - 1) * query.page_size

        total = await self._url_repo.count_by_query(mongo_query)
        docs = await self._url_repo.find_by_owner(
            query=mongo_query,
            sort_field=query.sort_by,
            sort_order=sort_order,
            skip=skip,
            limit=query.page_size,
        )

        has_next = (skip + len(docs)) < total
        duration_ms = int((time.perf_counter() - start_time) * 1000)

        log.info(
            "url_list_query",
            user_id=str(owner_id),
            page=query.page,
            page_size=query.page_size,
            sort_by=query.sort_by,
            sort_order="descending" if sort_order == -1 else "ascending",
            filter_count=len(mongo_query) - 1,  # subtract the base owner_id filter
            total=total,
            returned=len(docs),
            has_next=has_next,
            duration_ms=duration_ms,
        )

        return {
            "items": docs,
            "page": query.page,
            "pageSize": query.page_size,
            "total": total,
            "hasNext": has_next,
            "sortBy": query.sort_by,
            "sortOrder": "descending" if sort_order == -1 else "ascending",
        }

    # ── Private helpers ───────────────────────────────────────────────────────

    async def _dispatch(
        self, short_code: str
    ) -> tuple[UrlCacheData | None, SchemaVersion]:
        """
        Determine URL schema and fetch from the appropriate collection.

        Mirrors get_url_by_length_and_type() exactly:
          emoji → emojis, schema "emoji"
          7 chars → urlsV2 first, urls fallback
          6 chars → urls first, urlsV2 fallback
          other   → urlsV2 first, urls fallback
        """
        if is_emoji_alias(short_code):
            doc = await self._emoji_repo.find_by_id(short_code)
            if doc is not None:
                return (
                    _emoji_doc_to_cache(short_code, doc, self._system_default_domain),
                    SchemaVersion.EMOJI,
                )
            return None, SchemaVersion.EMOJI

        code_len = len(short_code)
        if code_len == 7:
            return await self._try_v2_then_v1(short_code)
        elif code_len == 6:
            return await self._try_v1_then_v2(short_code)
        else:
            return await self._try_v2_then_v1(short_code)

    async def _dispatch_custom_domain(
        self, short_code: str, domain: str
    ) -> tuple[UrlCacheData | None, SchemaVersion]:
        # Custom domains are v2-only by construction.
        v2_doc = await self._url_repo.find_by_alias(short_code, domain)
        if v2_doc is None:
            return None, SchemaVersion.V2
        return _v2_doc_to_cache(v2_doc), SchemaVersion.V2

    async def _try_v2_then_v1(
        self, short_code: str
    ) -> tuple[UrlCacheData | None, SchemaVersion]:
        v2_doc = await self._url_repo.find_by_alias(
            short_code, self._system_default_domain
        )
        if v2_doc is not None:
            return _v2_doc_to_cache(v2_doc), SchemaVersion.V2
        v1_doc = await self._legacy_repo.find_by_id(short_code)
        if v1_doc is not None:
            return (
                _legacy_doc_to_cache(short_code, v1_doc, self._system_default_domain),
                SchemaVersion.V1,
            )
        return None, SchemaVersion.V2

    async def _try_v1_then_v2(
        self, short_code: str
    ) -> tuple[UrlCacheData | None, SchemaVersion]:
        v1_doc = await self._legacy_repo.find_by_id(short_code)
        if v1_doc is not None:
            return (
                _legacy_doc_to_cache(short_code, v1_doc, self._system_default_domain),
                SchemaVersion.V1,
            )
        v2_doc = await self._url_repo.find_by_alias(
            short_code, self._system_default_domain
        )
        if v2_doc is not None:
            return _v2_doc_to_cache(v2_doc), SchemaVersion.V2
        return None, SchemaVersion.V2

    async def _populate_cache(
        self,
        short_code: str,
        url_cache_data: UrlCacheData,
        schema: SchemaVersion,
    ) -> None:
        """
        Cache the URL data according to caching rules:
          - v2 (any status): cache (minimal for non-ACTIVE)
          - v1 without max-clicks: cache
          - v1 with max-clicks: do NOT cache (total-clicks must be live)
          - emoji: do NOT cache
        """
        if schema == SchemaVersion.V2 or (
            schema == SchemaVersion.V1 and url_cache_data.max_clicks is None
        ):
            await self._url_cache.set(short_code, url_cache_data)

    async def _generate_unique_alias(self, *, domain: str | None = None) -> str:
        """Generate a 7-character alias not already in urlsV2 for *domain*."""
        target_domain = domain or self._system_default_domain
        for _ in range(10):
            candidate = generate_short_code_v2(7)
            if not await self._url_repo.check_alias_exists(candidate, target_domain):
                return candidate
        log.error("url_alias_generation_exhausted", domain=target_domain)
        raise AppError("Could not generate a unique alias; please try again")


# ── Module-level helpers ──────────────────────────────────────────────────────


def _raise_for_status(status: UrlStatus) -> None:
    if status == UrlStatus.BLOCKED:
        raise BlockedUrlError("URL is blocked")
    raise GoneError("URL has expired or is no longer active")


def _v2_doc_to_cache(doc: UrlV2Doc) -> UrlCacheData:
    return UrlCacheData(
        id=str(doc.id),
        alias=doc.alias,
        long_url=doc.long_url,
        block_bots=bool(doc.block_bots),
        password_hash=doc.password,
        expiration_time=(
            int(doc.expire_after.timestamp()) if doc.expire_after else None
        ),
        max_clicks=doc.max_clicks,
        url_status=doc.status,
        schema_version=SchemaVersion.V2,
        owner_id=str(doc.owner_id) if doc.owner_id else None,
        domain=doc.domain,
        meta_title=doc.meta_tags.title if doc.meta_tags else None,
        meta_description=doc.meta_tags.description if doc.meta_tags else None,
        meta_image=doc.meta_tags.image if doc.meta_tags else None,
        meta_color=doc.meta_tags.color if doc.meta_tags else None,
        meta_image_width=(
            doc.meta_tags.image_meta.width
            if doc.meta_tags and doc.meta_tags.image_meta
            else None
        ),
        meta_image_height=(
            doc.meta_tags.image_meta.height
            if doc.meta_tags and doc.meta_tags.image_meta
            else None
        ),
    )


def _legacy_doc_to_cache(
    short_code: str,
    doc: LegacyUrlDoc | EmojiUrlDoc,
    system_default_domain: str,
    schema_version: SchemaVersion = SchemaVersion.V1,
) -> UrlCacheData:
    """Convert a LegacyUrlDoc or EmojiUrlDoc to UrlCacheData.

    v1/emoji shorts only exist under the system default domain — they
    predate custom domains and won't ever be created elsewhere.
    """
    expiration_time = None
    if doc.expiration_time:
        expiration_time = int(doc.expiration_time.timestamp())
    return UrlCacheData(
        id=short_code,
        alias=short_code,
        long_url=doc.url,
        block_bots=bool(doc.block_bots),
        password_hash=doc.password,
        expiration_time=expiration_time,
        max_clicks=doc.max_clicks,
        url_status=UrlStatus.ACTIVE,
        schema_version=schema_version,
        total_clicks=doc.total_clicks,
        owner_id=None,
        domain=system_default_domain,
    )


def _emoji_doc_to_cache(
    short_code: str, doc: EmojiUrlDoc, system_default_domain: str
) -> UrlCacheData:
    return _legacy_doc_to_cache(
        short_code, doc, system_default_domain, schema_version=SchemaVersion.EMOJI
    )
