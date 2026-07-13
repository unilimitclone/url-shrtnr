"""
v2 emoji-alias policy — canonicalization, RGI-subset validation, and
generation-pool derivation. Pure, framework-agnostic, stateless.

Why a policy exists at all: browsers resolve any percent-encoded path, but
many emoji are byte-fragile (the same glyph can be produced with or without
an invisible ``U+FE0F`` variation selector) or don't render on major
platforms (ZWJ sequences split apart, regional-indicator flags show as bare
letters on Chromium/Windows, tag sequences can smuggle invisible data).
The v1 system accepted all of them; this module is the fix.

Accepted graphemes are RGI *fully-qualified* sequences that are either a
single codepoint (which, for single codepoints, implies default emoji
presentation — no ``U+FE0F`` ever needed) or a base + skin-tone modifier.
Everything else — VS16-dependent symbols, ZWJ sequences, keycaps, flags,
tag sequences, standalone components — is rejected by construction.

Legacy resolution stays on ``shared.validators.is_emoji_alias`` (lenient,
no policy); THIS module governs everything newly created. Like the other
``shared`` validators, nothing here reads settings — every knob is a
parameter with a module-level default, enforced by the service layer.
"""

from __future__ import annotations

import re
import unicodedata
from functools import lru_cache
from typing import Literal
from urllib.parse import unquote

import emoji
import regex

# Acceptance cap for custom aliases: Emoji 15.1 renders on iOS 17.4+/
# Android 14+/Windows 11 23H2+ — two OS generations of headroom.
DEFAULT_ACCEPT_MAX_VERSION: float = 15.1
# Generation cap: Windows 10's Segoe UI Emoji froze at Emoji 12.0 (May 2019
# was its last emoji update); auto-generated codes must render everywhere.
DEFAULT_GENERATE_MAX_VERSION: float = 12.0
DEFAULT_MAX_GRAPHEMES: int = 15

EmojiAliasVerdict = Literal["ok", "empty", "length", "policy"]

_ALNUM_ALIAS_RE = re.compile(r"[a-zA-Z0-9_-]*\Z")
_GRAPHEME_RE = regex.compile(r"\X")
_VS16 = "️"
_SKIN_TONE_MIN = "\U0001f3fb"
_SKIN_TONE_MAX = "\U0001f3ff"
_REGIONAL_INDICATOR_RANGE = (0x1F1E6, 0x1F1FF)


def is_emoji_candidate(alias: str) -> bool:
    """Return True if *alias* contains any character outside ``[A-Za-z0-9_-]``.

    Coarse shape test used to route input onto the emoji validation path.
    NOT a validity check — garbage input is also a "candidate" and must be
    rejected downstream by :func:`is_emoji_only_shape` / :func:`check_emoji_alias`.
    """
    return _ALNUM_ALIAS_RE.fullmatch(alias) is None


def canonicalize_emoji_alias(alias: str) -> str:
    """Return the canonical stored/lookup form of an emoji alias.

    unquote → NFC → strip ``U+FE0F``. Idempotent, and a no-op on already
    canonical input. Routes may have unquoted the path once already; the
    second unquote here is harmless because neither accepted grammar
    (alphanumeric or policy-valid emoji) contains ``%``.

    The accepted emoji subset never *needs* VS16 (single-codepoint
    fully-qualified emoji have default emoji presentation), so stray
    selectors from keyboards/copy-paste are dropped rather than 404ing —
    ``⭐️`` and ``⭐`` resolve to the same link.
    """
    decoded = unicodedata.normalize("NFC", unquote(alias))
    return decoded.replace(_VS16, "")


def is_emoji_only_shape(alias: str) -> bool:
    """Structural gate: every grapheme of *alias* is emoji-shaped.

    A grapheme is emoji-shaped when its canonical form appears in the
    ``emoji`` package's ``EMOJI_DATA`` under *any* qualification status —
    this deliberately includes ZWJ sequences, flags, and keycaps so that
    DTO-level checks can reject *mixed/garbage* input (422) while leaving
    policy decisions (400) to :func:`check_emoji_alias`.
    """
    canonical = canonicalize_emoji_alias(alias)
    if not canonical:
        return False
    return all(g in emoji.EMOJI_DATA for g in _GRAPHEME_RE.findall(canonical))


def check_emoji_alias(
    canonical: str,
    *,
    max_graphemes: int = DEFAULT_MAX_GRAPHEMES,
    max_version: float = DEFAULT_ACCEPT_MAX_VERSION,
) -> EmojiAliasVerdict:
    """Validate an already-canonicalized alias against the emoji policy.

    Callers must pass the output of :func:`canonicalize_emoji_alias`.
    Returns the first failing check: ``"empty"``, ``"length"`` (grapheme
    count above *max_graphemes*), ``"policy"`` (any grapheme outside the
    accepted subset), or ``"ok"``.
    """
    if not canonical:
        return "empty"
    graphemes = _GRAPHEME_RE.findall(canonical)
    if len(graphemes) > max_graphemes:
        return "length"
    if all(_grapheme_accepted(g, max_version) for g in graphemes):
        return "ok"
    return "policy"


def _grapheme_accepted(grapheme: str, max_version: float) -> bool:
    """One grapheme passes policy: RGI fully-qualified, version-capped, and
    single-codepoint or base+skin-tone.

    Single codepoint + fully_qualified implies ``Emoji_Presentation=Yes``
    (text-default symbols like ``☺`` are *unqualified* without VS16), so no
    separate presentation table is needed. The 2-codepoint arm only admits
    skin-tone modifiers — flags (regional-indicator pairs), keycaps, ZWJ and
    tag sequences all fail here or on the status check.
    """
    data = emoji.EMOJI_DATA.get(grapheme)
    if data is None or data["status"] != emoji.STATUS["fully_qualified"]:
        return False
    if data.get("E", float("inf")) > max_version:
        return False
    if len(grapheme) == 1:
        return True
    return len(grapheme) == 2 and _SKIN_TONE_MIN <= grapheme[1] <= _SKIN_TONE_MAX


@lru_cache(maxsize=4)
def generation_pool(
    max_version: float = DEFAULT_GENERATE_MAX_VERSION,
) -> tuple[str, ...]:
    """Derive the auto-generation emoji pool from ``EMOJI_DATA``.

    Single-codepoint, fully-qualified, ``E <= max_version``, excluding
    regional indicators (belt-and-suspenders — single indicators are not
    fully-qualified anyway). Derived rather than checked in as an artifact
    so the pool can never drift from the validator that accepts its output;
    ``emoji`` is version-pinned, and unit tests assert every pool entry
    passes :func:`check_emoji_alias`.
    """
    lo, hi = _REGIONAL_INDICATOR_RANGE
    pool = tuple(
        e
        for e, data in emoji.EMOJI_DATA.items()
        if len(e) == 1
        and data["status"] == emoji.STATUS["fully_qualified"]
        and data.get("E", float("inf")) <= max_version
        and not (lo <= ord(e) <= hi)
    )
    if not pool:
        raise ValueError(f"empty emoji generation pool for max_version={max_version}")
    return pool


def vs16_insensitive_pattern(canonical: str) -> str:
    """Anchored regex matching *canonical* with an optional ``U+FE0F`` after
    each codepoint.

    Used for collision checks against the legacy ``emojis`` collection,
    whose ``_id``s may contain historically-accepted variation selectors —
    a legacy ``⭐️🎉`` must block a new canonical ``⭐🎉``.
    """
    return (
        "^" + "".join(re.escape(char) + f"{_VS16}?" for char in canonical) + "$"
    )
