"""Safety's operator embeds, composed over the shared ``OpsNotifier``.

``infrastructure/ops_notify`` knows Discord; it does not know what a block
is. Everything safety-shaped lives here: which fields a block carries, that
scope gets its own line, that a follow-up never rides inside the reason,
and that the screenshot the model judged travels with the verdict.
"""

from __future__ import annotations

from typing import Any

from infrastructure.ops_notify import OpsNotifier

ACTION_COLOR = 15548997  # red: automatic enforcement happened
REVIEW_COLOR = 16705372  # yellow: a human decision is needed


def _code(value: object) -> str:
    return f"```{value}```"


class SafetyNotifier:
    def __init__(self, ops: OpsNotifier) -> None:
        self._ops = ops

    async def safety_action(
        self,
        *,
        host: str,
        reason: str,
        trigger: str,
        blocked_count: int,
        legacy_count: int,
        sample_url: str | None,
        scope: str = "",
        screenshot: bytes | None = None,
        follow_up: str = "",
    ) -> bool:
        """Enforcement already happened; this states the action taken.
        ``scope`` is its own field because "host-wide" and "one link" are
        read very differently by the person deciding whether to intervene,
        and ``follow_up`` is separate so a link-scoped block never reads
        "host-wide decision..." beside a Scope that says otherwise."""
        fields: list[dict[str, Any]] = [
            {"name": "Destination Host", "value": _code(host)},
            {"name": "Scope", "value": _code(scope or "unspecified")},
            {"name": "Reason", "value": _code(reason)},
            {"name": "Trigger", "value": _code(trigger)},
            {"name": "Links Blocked (v2)", "value": _code(blocked_count)},
        ]
        if legacy_count:
            fields.append(
                {"name": "Legacy v1/emoji Blocked", "value": _code(legacy_count)}
            )
        if sample_url:
            fields.append({"name": "Sample URL", "value": _code(sample_url)})
        if follow_up:
            fields.append({"name": "Follow-up", "value": _code(follow_up)})
        return await self._ops.send_embed(
            channel="report",
            title="Safety: destination auto-blocked",
            color=ACTION_COLOR,
            fields=fields,
            image=screenshot,
            kind="safety_action",
        )

    async def safety_review(
        self,
        *,
        host: str,
        trigger: str,
        sample_url: str | None,
        context: dict | None,
        screenshot: bytes | None = None,
    ) -> bool:
        """No source could judge this destination; a human decision is
        needed. Carries the trigger context so the decision takes seconds."""
        fields: list[dict[str, Any]] = [
            {"name": "Destination Host", "value": _code(host)},
            {"name": "Trigger", "value": _code(trigger)},
        ]
        if sample_url:
            fields.append({"name": "Sample URL", "value": _code(sample_url)})
        if context:
            lines = [f"{k}: {v}" for k, v in list(context.items())[:8]]
            fields.append({"name": "Context", "value": _code("\n".join(lines))})
        return await self._ops.send_embed(
            channel="report",
            title="Safety: review needed",
            color=REVIEW_COLOR,
            fields=fields,
            image=screenshot,
            kind="safety_review",
        )
