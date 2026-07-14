"""
Response DTO for GET /api/v1/emoji-set.

A static, build-time-derived catalogue of the emoji-alias acceptance
policy so clients (e.g. an emoji picker) have one source of truth instead
of replicating the rules. DTO serializes only — the derivation lives in
``shared.emoji_policy`` and is assembled in the route.
"""

from __future__ import annotations

from pydantic import Field

from schemas.dto.base import ResponseBase


class EmojiSetResponse(ResponseBase):
    """The accepted / auto-generated emoji sets and their caps.

    Values are RAW emoji characters in canonical form (no ``U+FE0F``
    variation selector), matching how aliases are stored and echoed.
    """

    accept_max_version: float = Field(
        description="Newest Unicode emoji version a custom alias may use."
    )
    generate_max_version: float = Field(
        description="Cap for auto-generated emoji aliases (lower, for older "
        "platform coverage)."
    )
    max_graphemes: int = Field(
        description="Maximum number of emoji graphemes allowed in one alias."
    )
    accepted: list[str] = Field(
        description="Every single-codepoint emoji a user may choose, at the "
        "acceptance cap. This is the picker's list. Skin-tone variants are "
        "NOT enumerated: the base emoji suffices and skin tone is a "
        "client-side modifier appended to the base."
    )
    generate: list[str] = Field(
        description="The server's auto-generation pool at the generation cap, "
        "exposed so a client dice suggester can match server auto-gen if it "
        "wants. A subset of the accepted space (regional indicators removed)."
    )
