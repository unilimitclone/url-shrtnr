"""Edge cache wire contract — KV key format and entry shape.

Consumed by the TS Worker in ``edge/spoo-edge-cache/``; pinned from both
sides by ``edge/spoo-edge-cache/contract/`` (schema + fixtures). Changes
here are cross-language: update the fixtures and the Worker in the same
commit. Promotion policy lives in :mod:`services.edge_cache.promotion`
and can change freely; this module should stay stable.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict


def cache_key(domain: str, short_code: str) -> str:
    """``cache:{domain}:{code}`` — the Worker derives the same key from
    the request Host (lowercased, ``www.`` stripped) and path."""
    return f"cache:{domain}:{short_code}"


class EdgeCacheEntry(BaseModel):
    """The KV value the Worker serves from. Schema pinned by
    ``edge/spoo-edge-cache/contract/entry.schema.json``."""

    model_config = ConfigDict(frozen=True)

    type: Literal["redirect"] = "redirect"
    url: str
    status: int = 302
