"""ClickEvent — the serializable fact emitted for every tracked redirect.

The event snapshots everything the click pipeline needs (including the
resolved ``UrlCacheData``) so consumers never re-resolve the URL — a
re-resolve would reintroduce the Mongo round-trip the async pipeline
exists to remove.

Wire format
-----------
Events travel as flat fields on a Redis Stream entry:

    {"v": "1", "type": "click.recorded", "__data__": "<event json>"}

``__data__`` is the payload key FastStream's parser extracts natively, so
subscriber handlers receive the decoded event dict without custom parsers,
while the producer side stays plain redis-py (``XADD``) with no framework
dependency on the hot path. ``v``/``type`` ride alongside for redis-cli
introspection and future multi-event streams.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, ConfigDict, Field
from pydantic import ValidationError as PydanticValidationError

from infrastructure.cache.url_cache import UrlCacheData
from infrastructure.logging import get_logger

log = get_logger(__name__)

STREAM_FIELD_VERSION = "v"
STREAM_FIELD_TYPE = "type"
STREAM_FIELD_DATA = "__data__"
EVENT_TYPE_CLICK = "click.recorded"
_WIRE_VERSION = "1"


class ClickEvent(BaseModel):
    """Immutable fact: a redirect was served and its click should be tracked."""

    model_config = ConfigDict(frozen=True)

    short_code: str
    # Resolved schema key ("v1" | "v2" | "emoji") — distinct from
    # url.schema_version (emoji aliases resolve with schema_version "v1").
    # Named schema_key because `schema` shadows a BaseModel attribute.
    schema_key: str
    is_emoji: bool
    url: UrlCacheData
    client_ip: str
    user_agent: str
    referrer: str | None
    cf_city: str | None
    redirect_ms: int
    enqueued_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )


def to_stream_fields(event: ClickEvent) -> dict[str, str]:
    """Encode an event as flat string fields for ``XADD``."""
    return {
        STREAM_FIELD_VERSION: _WIRE_VERSION,
        STREAM_FIELD_TYPE: EVENT_TYPE_CLICK,
        STREAM_FIELD_DATA: event.model_dump_json(),
    }


def from_stream_fields(fields: dict[str, str]) -> ClickEvent | None:
    """Decode raw stream entry fields back into a ClickEvent.

    Returns None (and logs) on malformed payloads — a payload that cannot
    parse today can never parse, so callers drop it instead of letting it
    poison-pill a consumer group.
    """
    raw = fields.get(STREAM_FIELD_DATA)
    if not raw:
        log.warning("click_event_missing_data", fields=list(fields.keys()))
        return None
    try:
        return ClickEvent.model_validate_json(raw)
    except PydanticValidationError:
        log.warning("click_event_malformed", raw=raw[:300])
        return None


def click_event_from_payload(payload: Any) -> ClickEvent | None:
    """Decode an already-JSON-parsed payload (the FastStream handler path).

    FastStream extracts and JSON-decodes the ``__data__`` field before the
    handler runs, so subscribers receive a dict rather than raw fields.
    Same drop-don't-poison semantics as :func:`from_stream_fields`.
    """
    if not isinstance(payload, dict):
        log.warning("click_event_payload_not_dict", payload_type=type(payload).__name__)
        return None
    try:
        return ClickEvent.model_validate(payload)
    except PydanticValidationError:
        log.warning("click_event_malformed", raw=str(payload)[:300])
        return None
