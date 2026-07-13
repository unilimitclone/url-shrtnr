from __future__ import annotations

import re
from urllib.parse import quote

import emoji as _emoji
import pytest
import regex

from shared.emoji_policy import (
    DEFAULT_ACCEPT_MAX_VERSION,
    DEFAULT_GENERATE_MAX_VERSION,
    canonicalize_emoji_alias,
    check_emoji_alias,
    generation_pool,
    is_emoji_candidate,
    is_emoji_only_shape,
    vs16_insensitive_pattern,
)

VS16 = "️"

STAR = "⭐"  # ⭐ single cp, fully-qualified, E0.6
PARTY = "\U0001f389"  # 🎉 single cp, E0.6
THUMBS_MEDIUM = "\U0001f44d\U0001f3fd"  # 👍🏽 base + skin tone, E1.0
SMILEY_TEXT_DEFAULT = "☺"  # ☺ unqualified without VS16
WOMAN_TECHNOLOGIST = "\U0001f469‍\U0001f4bb"  # 👩‍💻 ZWJ sequence
RAINBOW_FLAG = "\U0001f3f3️‍\U0001f308"  # 🏳️‍🌈 ZWJ sequence
KEYCAP_ONE = "1️⃣"  # 1️⃣
US_FLAG = "\U0001f1fa\U0001f1f8"  # 🇺🇸 regional indicators
ENGLAND_FLAG = "\U0001f3f4\U000e0067\U000e0062\U000e0065\U000e006e\U000e0067\U000e007f"  # 🏴󠁧󠁢󠁥󠁮󠁧󠁿 tag sequence
SKIN_SWATCH = "\U0001f3ff"  # 🏿 standalone component
MELTING_FACE = "\U0001fae0"  # 🫠 E14.0
SHAKING_FACE = "\U0001fae8"  # 🫨 E15.0


class TestIsEmojiCandidate:
    @pytest.mark.parametrize("alias", ["mylink", "a-b_c9", "", "ABC123"])
    def test_alnum_is_not_candidate(self, alias):
        assert is_emoji_candidate(alias) is False

    @pytest.mark.parametrize("alias", [STAR, PARTY * 3, "abc" + PARTY, "café", "%F0"])
    def test_anything_else_is_candidate(self, alias):
        assert is_emoji_candidate(alias) is True


class TestCanonicalizeEmojiAlias:
    def test_strips_vs16(self):
        assert canonicalize_emoji_alias(STAR + VS16 + PARTY) == STAR + PARTY

    def test_unquotes_percent_encoding(self):
        assert canonicalize_emoji_alias(quote(STAR + PARTY)) == STAR + PARTY

    def test_unquotes_then_strips(self):
        assert canonicalize_emoji_alias(quote(STAR + VS16)) == STAR

    def test_nfc_normalizes(self):
        # e + combining acute → é (non-emoji input is normalized, not mangled)
        assert canonicalize_emoji_alias("é") == "é"

    def test_idempotent(self):
        once = canonicalize_emoji_alias(STAR + VS16 + THUMBS_MEDIUM)
        assert canonicalize_emoji_alias(once) == once

    def test_noop_on_alnum(self):
        assert canonicalize_emoji_alias("mylink") == "mylink"


class TestIsEmojiOnlyShape:
    @pytest.mark.parametrize(
        "alias",
        [
            STAR,
            PARTY * 3,
            THUMBS_MEDIUM,
            # Policy-rejected but emoji-SHAPED — must pass the structural
            # gate so they reach the service and fail as policy (400),
            # not as a DTO 422.
            WOMAN_TECHNOLOGIST,
            US_FLAG,
            KEYCAP_ONE,
            ENGLAND_FLAG,
            SMILEY_TEXT_DEFAULT + VS16,
        ],
    )
    def test_emoji_shaped(self, alias):
        assert is_emoji_only_shape(alias) is True

    @pytest.mark.parametrize(
        "alias",
        ["abc", "abc" + PARTY, PARTY + "x", "", " ", STAR + " " + STAR, "café"],
    )
    def test_mixed_or_garbage_rejected(self, alias):
        assert is_emoji_only_shape(alias) is False


class TestCheckEmojiAlias:
    @pytest.mark.parametrize(
        "alias",
        [STAR, PARTY, THUMBS_MEDIUM, STAR + PARTY + THUMBS_MEDIUM, PARTY * 15],
    )
    def test_accepted(self, alias):
        assert check_emoji_alias(alias) == "ok"

    def test_empty(self):
        assert check_emoji_alias("") == "empty"

    def test_too_many_graphemes(self):
        assert check_emoji_alias(PARTY * 16) == "length"

    def test_grapheme_cap_configurable(self):
        assert check_emoji_alias(PARTY * 3, max_graphemes=2) == "length"

    @pytest.mark.parametrize(
        "alias",
        [
            SMILEY_TEXT_DEFAULT,  # unqualified without VS16 (byte-fragile)
            WOMAN_TECHNOLOGIST,  # ZWJ sequence
            canonicalize_emoji_alias(RAINBOW_FLAG),  # ZWJ sequence
            canonicalize_emoji_alias(KEYCAP_ONE),  # keycap
            US_FLAG,  # regional-indicator flag
            ENGLAND_FLAG,  # tag sequence
            SKIN_SWATCH,  # standalone component
            "abc",  # not emoji at all
        ],
    )
    def test_policy_rejected(self, alias):
        assert check_emoji_alias(alias) == "policy"

    def test_version_cap(self):
        assert check_emoji_alias(SHAKING_FACE, max_version=12.0) == "policy"
        assert check_emoji_alias(SHAKING_FACE, max_version=15.1) == "ok"
        assert check_emoji_alias(MELTING_FACE, max_version=12.0) == "policy"
        assert (
            check_emoji_alias(MELTING_FACE, max_version=DEFAULT_ACCEPT_MAX_VERSION)
            == "ok"
        )

    def test_expects_canonical_input(self):
        # Raw VS16 forms are the caller's job to canonicalize first;
        # uncanonicalized input fails closed rather than resolving.
        assert check_emoji_alias(STAR + VS16) == "policy"


class TestGenerationPool:
    def test_pool_non_empty_and_stable(self):
        pool = generation_pool()
        assert len(pool) > 500
        assert pool is generation_pool()  # lru_cache

    def test_all_single_codepoint(self):
        assert all(len(e) == 1 for e in generation_pool())

    def test_every_entry_passes_acceptance_policy(self):
        # THE invariant: the generator can never emit something the
        # validator rejects. Turns any future `emoji` package bump that
        # breaks this into an explicit test failure.
        for e in generation_pool():
            assert check_emoji_alias(e) == "ok", f"pool entry rejected: {e!r}"

    def test_version_cap_respected(self):
        for e in generation_pool():
            assert _emoji.EMOJI_DATA[e]["E"] <= DEFAULT_GENERATE_MAX_VERSION

    def test_no_regional_indicators(self):
        assert not any(0x1F1E6 <= ord(e) <= 0x1F1FF for e in generation_pool())

    def test_wider_cap_is_superset(self):
        narrow, wide = set(generation_pool(12.0)), set(generation_pool(15.1))
        assert narrow < wide

    def test_empty_pool_raises(self):
        with pytest.raises(ValueError):
            generation_pool(0.1)


class TestVs16InsensitivePattern:
    def test_matches_canonical_and_vs16_variants(self):
        pattern = re.compile(vs16_insensitive_pattern(STAR + PARTY))
        assert pattern.fullmatch(STAR + PARTY)
        assert pattern.fullmatch(STAR + VS16 + PARTY)
        assert pattern.fullmatch(STAR + PARTY + VS16)
        assert pattern.fullmatch(STAR + VS16 + PARTY + VS16)

    def test_rejects_other_aliases(self):
        pattern = re.compile(vs16_insensitive_pattern(STAR + PARTY))
        assert pattern.fullmatch(STAR) is None
        assert pattern.fullmatch(PARTY + STAR) is None
        assert pattern.fullmatch(STAR + PARTY + PARTY) is None

    def test_escapes_regex_metacharacters(self):
        # Defense in depth: canonical input should never contain these,
        # but the pattern must stay literal if it ever does.
        pattern = re.compile(vs16_insensitive_pattern("a.b"))
        assert pattern.fullmatch("a.b")
        assert pattern.fullmatch("axb") is None


class TestGraphemeSegmentation:
    """Pin the \\X behavior the policy depends on."""

    @pytest.mark.parametrize(
        ("s", "count"),
        [
            (THUMBS_MEDIUM, 1),
            (US_FLAG, 1),
            (US_FLAG * 2, 2),
            (WOMAN_TECHNOLOGIST, 1),
            (ENGLAND_FLAG, 1),
            (STAR + PARTY, 2),
        ],
    )
    def test_grapheme_counts(self, s, count):
        assert len(regex.findall(r"\X", s)) == count
