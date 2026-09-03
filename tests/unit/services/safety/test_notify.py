"""SafetyNotifier composes the block and review embeds over the shared
OpsNotifier. What the fields SAY is owned here; how Discord gets them is not."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from services.safety.notify import ACTION_COLOR, REVIEW_COLOR, SafetyNotifier


def _notifier():
    ops = AsyncMock()
    ops.send_embed = AsyncMock(return_value=True)
    return SafetyNotifier(ops), ops


def _fields(ops) -> dict[str, str]:
    return {f["name"]: f["value"] for f in ops.send_embed.await_args.kwargs["fields"]}


def _action(n, **over):
    base = dict(
        host="evil.example",
        reason="fake bank login",
        trigger="sweep",
        blocked_count=3,
        legacy_count=0,
        sample_url="https://evil.example/x",
    )
    base.update(over)
    return n.safety_action(**base)


class TestActionEmbed:
    @pytest.mark.asyncio
    async def test_scope_is_its_own_field_and_reason_is_only_the_reason(self):
        """ "host-wide" and "one link" are read very differently by the person
        deciding whether to intervene."""
        n, ops = _notifier()
        await _action(n, scope="pattern: ^https://sites\\.google\\.com/view/evil/.*")
        f = _fields(ops)
        assert f["Scope"] == "```pattern: ^https://sites\\.google\\.com/view/evil/.*```"
        assert f["Reason"] == "```fake bank login```"
        kw = ops.send_embed.await_args.kwargs
        assert kw["channel"] == "report" and kw["color"] == ACTION_COLOR
        assert kw["title"] == "Safety: destination auto-blocked"

    @pytest.mark.asyncio
    async def test_missing_scope_is_named_not_omitted(self):
        n, ops = _notifier()
        await _action(n)
        assert _fields(ops)["Scope"] == "```unspecified```"

    @pytest.mark.asyncio
    async def test_follow_up_is_separate_from_reason(self):
        """A link-scoped block must never read "host-wide decision..." inside
        its Reason."""
        n, ops = _notifier()
        await _action(
            n,
            scope="the judged link only",
            follow_up="host-wide decision sent to investigation",
        )
        f = _fields(ops)
        assert f["Reason"] == "```fake bank login```"
        assert f["Follow-up"] == "```host-wide decision sent to investigation```"

    @pytest.mark.asyncio
    async def test_no_follow_up_no_field(self):
        n, ops = _notifier()
        await _action(n)
        assert "Follow-up" not in _fields(ops)

    @pytest.mark.asyncio
    async def test_legacy_count_only_when_nonzero(self):
        n, ops = _notifier()
        await _action(n, legacy_count=0)
        assert "Legacy v1/emoji Blocked" not in _fields(ops)
        await _action(n, legacy_count=7)
        assert _fields(ops)["Legacy v1/emoji Blocked"] == "```7```"

    @pytest.mark.asyncio
    async def test_screenshot_is_handed_over_as_the_image(self):
        n, ops = _notifier()
        await _action(n, screenshot=b"webp!")
        assert ops.send_embed.await_args.kwargs["image"] == b"webp!"

    @pytest.mark.asyncio
    async def test_no_screenshot_means_no_image(self):
        n, ops = _notifier()
        await _action(n)
        assert ops.send_embed.await_args.kwargs["image"] is None


class TestReviewEmbed:
    @pytest.mark.asyncio
    async def test_carries_context_and_image(self):
        n, ops = _notifier()
        await n.safety_review(
            host="h",
            trigger="report",
            sample_url="https://h/x",
            context={"classification": "uncertain", "confidence": "low"},
            screenshot=b"shot",
        )
        kw = ops.send_embed.await_args.kwargs
        assert kw["title"] == "Safety: review needed" and kw["color"] == REVIEW_COLOR
        assert kw["image"] == b"shot"
        f = _fields(ops)
        assert "classification: uncertain" in f["Context"]
        assert f["Sample URL"] == "```https://h/x```"
