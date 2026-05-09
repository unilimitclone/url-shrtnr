"""
URL document models.

Three separate schemas map to three MongoDB collections:

  UrlV2Doc     → urlsV2     (current schema, ObjectId _id, separate alias field)
  LegacyUrlDoc → urls       (v1 schema, short_code is _id, hyphenated field names,
                              embedded analytics, plaintext password)
  EmojiUrlDoc  → emojis     (same structure as LegacyUrlDoc)
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import ConfigDict, Field, field_validator

from schemas.models.base import ANONYMOUS_OWNER_ID, MongoBaseModel, PyObjectId


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
