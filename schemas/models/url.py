"""
URL document models.

Three separate schemas map to three MongoDB collections:

  UrlV2Doc     → urlsV2     (current schema, ObjectId _id, separate alias field)
  LegacyUrlDoc → urls       (v1 schema, short_code is _id, hyphenated field names,
                              embedded analytics, plaintext password)
  EmojiUrlDoc  → emojis     (same structure as LegacyUrlDoc)
"""

from __future__ import annotations

import re
from datetime import datetime
from enum import Enum
from typing import Any
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field, field_validator

from schemas.models.base import ANONYMOUS_OWNER_ID, MongoBaseModel, PyObjectId

_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")


class UrlStatus(str, Enum):
    """Status values for v2 URLs."""

    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"
    EXPIRED = "EXPIRED"
    BLOCKED = "BLOCKED"


class SchemaVersion(str, Enum):
    """URL collection / schema version identifiers."""

    V2 = "v2"
    V1 = "v1"
    EMOJI = "emoji"


# og:image rendering cliffs, documented per platform. Above/below these,
# platforms silently degrade or drop the image — we warn, never reject
# (the cliffs are platform-specific; the image may be fine elsewhere).
WHATSAPP_RELIABLE_BYTES = 300_000  # WhatsApp silently drops above ~this
MIN_IMAGE_SIDE_PX = 200  # below: Facebook/WhatsApp may drop entirely
LARGE_CARD_MIN_WIDTH_PX = 600  # below: Facebook demotes to small thumbnail
MAX_ASPECT_RATIO = 4  # above 4:1: WhatsApp drops


class MetaImageMeta(BaseModel):
    """Validation metadata for meta_tags.image — written by the upload
    path (synchronously) or the async image validator, never by clients."""

    width: int | None = None
    height: int | None = None
    bytes: int | None = None
    content_type: str | None = None
    checked_at: datetime


class LinkMetaTags(BaseModel):
    """Custom social-preview tags. Presence on a URL = feature enabled.

    title is mandatory (a card without one renders broken everywhere).
    image is an https URL (R2-hosted or external; data URIs are converted
    to R2 URLs before this model is built); SVG rejected — no preview
    crawler renders it. color = Discord embed border (theme-color).
    """

    title: str = Field(min_length=1, max_length=120)
    description: str | None = Field(default=None, max_length=240)
    image: str | None = Field(default=None, max_length=2048)
    color: str | None = Field(default=None, pattern=r"^#[0-9a-fA-F]{6}$")
    image_meta: MetaImageMeta | None = None
    updated_at: datetime | None = None
    updated_ip: str | None = None  # audit trail, mirrors creation_ip

    @field_validator("title", "description", mode="before")
    @classmethod
    def _strip_control(cls, v: Any) -> Any:
        if isinstance(v, str):
            v = _CONTROL_CHARS_RE.sub("", v).strip()
        return v

    @field_validator("image")
    @classmethod
    def _image_https_no_svg(cls, v: str | None) -> str | None:
        if v is None:
            return None
        if not v.startswith("https://"):
            raise ValueError("image must be an https:// URL")
        if urlparse(v).path.lower().endswith(".svg"):
            raise ValueError("SVG images are not supported by preview crawlers")
        return v

    def image_warnings(self) -> list[str]:
        """Platform-cliff notes for the og:image, derived from image_meta.

        Empty until image_meta exists — for external https images that's
        after async validation records it; uploads sniff synchronously.
        Unknown dimensions skip the dimension checks rather than guess.
        """
        im = self.image_meta
        if im is None:
            return []
        warnings: list[str] = []
        if im.bytes and im.bytes > WHATSAPP_RELIABLE_BYTES:
            warnings.append("image exceeds 300KB; WhatsApp may silently drop it")
        if im.width and im.height:
            if im.width < MIN_IMAGE_SIDE_PX or im.height < MIN_IMAGE_SIDE_PX:
                warnings.append(
                    "image is smaller than 200x200; Facebook and WhatsApp may "
                    "drop it entirely"
                )
            elif im.width < LARGE_CARD_MIN_WIDTH_PX:
                warnings.append(
                    "image is narrower than 600px; Facebook renders a small "
                    "thumbnail instead of the large card (1200x630 recommended)"
                )
            if max(im.width, im.height) > MAX_ASPECT_RATIO * min(im.width, im.height):
                warnings.append(
                    "image aspect ratio exceeds 4:1; WhatsApp drops extreme ratios"
                )
        return warnings


class UrlV2Doc(MongoBaseModel):
    """Document model for the `urlsV2` collection.

    password stores an argon2 hash. owner_id uses ANONYMOUS_OWNER_ID for
    unowned URLs. domain scopes alias uniqueness via the compound
    `(domain, alias)` index.
    """

    alias: str
    owner_id: PyObjectId = Field(default=ANONYMOUS_OWNER_ID)
    domain: str

    @field_validator("owner_id", mode="before")
    @classmethod
    def _coerce_null_owner(cls, v: Any) -> Any:
        return v if v is not None else ANONYMOUS_OWNER_ID

    @field_validator("domain", mode="before")
    @classmethod
    def _normalise_domain(cls, v: Any) -> str:
        # Reject empty so a forgotten domain on insert can't silently shadow
        # a real short under the unique compound index. Strip first so
        # whitespace-only input is also caught.
        if v is None:
            raise ValueError(
                "domain is required — pass settings.system_default_domain or "
                "an explicit custom domain fqdn"
            )
        normalised = str(v).strip()
        if normalised == "":
            raise ValueError(
                "domain is required — pass settings.system_default_domain or "
                "an explicit custom domain fqdn"
            )
        return normalised.lower().rstrip(".")

    created_at: datetime
    creation_ip: str | None = None
    long_url: str
    password: str | None = None
    block_bots: bool | None = None
    max_clicks: int | None = Field(default=None, ge=0)
    expire_after: datetime | None = None
    status: UrlStatus = UrlStatus.ACTIVE
    private_stats: bool | None = True  # None for anonymous/unowned URLs
    meta_tags: LinkMetaTags | None = None
    total_clicks: int = Field(default=0, ge=0)
    last_click: datetime | None = None
    updated_at: datetime | None = None


class LegacyUrlDoc(MongoBaseModel):
    """
    Document model for the `urls` collection (v1 schema).

    Key differences from v2:
    - `_id` IS the short code string (not an ObjectId).
    - Field names use hyphens: `max-clicks`, `total-clicks`, `block-bots`, etc.
        Pydantic field aliases map these to valid Python identifiers.
    - Analytics are embedded directly on the URL document.
    - Password is stored in plaintext.
    - No owner_id, no status field.

    Note: `id` inherited from MongoBaseModel is typed as Optional[PyObjectId],
    but for v1 documents it holds a plain string. We override it here with
    Optional[Any] and rely on from_mongo() to pass through whatever _id value
    MongoDB returns. Repositories never interpret this field as an ObjectId.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        arbitrary_types_allowed=True,
    )

    # _id is the short code string for v1 — override base type
    id: Any | None = Field(default=None, alias="_id")

    url: str
    password: str | None = None

    # Hyphenated field names — use aliases matching exact MongoDB keys
    max_clicks: int | None = Field(default=None, alias="max-clicks")
    total_clicks: int = Field(default=0, alias="total-clicks")
    block_bots: bool | None = Field(default=None, alias="block-bots")
    expiration_time: datetime | None = Field(default=None, alias="expiration-time")
    last_click: str | None = Field(default=None, alias="last-click")
    last_click_browser: str | None = Field(default=None, alias="last-click-browser")
    last_click_os: str | None = Field(default=None, alias="last-click-os")
    last_click_country: str | None = Field(default=None, alias="last-click-country")

    # Embedded analytics (dynamic dict fields — not typed further to preserve
    # the arbitrary key structure used for country/browser/os/referrer tracking)
    ips: list[str] = Field(default_factory=list)
    counter: dict[str, int] = Field(default_factory=dict)
    unique_counter: dict[str, int] = Field(default_factory=dict)
    country: dict[str, Any] = Field(default_factory=dict)
    browser: dict[str, Any] = Field(default_factory=dict)
    os_name: dict[str, Any] = Field(default_factory=dict)
    referrer: dict[str, Any] = Field(default_factory=dict)
    bots: dict[str, int] = Field(default_factory=dict)
    average_redirection_time: float = 0.0


class EmojiUrlDoc(LegacyUrlDoc):
    """
    Document model for the `emojis` collection.

    Identical structure to LegacyUrlDoc — the only difference is which
    MongoDB collection it lives in. Repositories use the correct collection.
    """
