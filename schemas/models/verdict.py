"""Document model for the ``safety_verdicts`` collection.

One verdict per destination HOST — many short links to one scam host share
a single judgment, computed once by whichever detection layer got there
first and enforced by reading, never recomputing, at the edges. Host
granularity (not registrable domain) keeps shared platforms (workers.dev,
free hosts) from being collectively punished; domain-wide action stays a
deliberate operator move.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import Field

from schemas.enums.safety import VerdictTier
from schemas.models.base import MongoBaseModel


class VerdictDoc(MongoBaseModel):
    host: str
    registrable_domain: str = ""
    # One example URL that led to this verdict, for review context.
    sample_url: str | None = None
    tier: VerdictTier
    # Human-readable reason string ("matched blocklist pattern …"); doubles
    # as the audit trail for appeals.
    reason: str | None = None
    # Which engine produced it: "local_feeds" now, "llm"/"human" later.
    source: str = "local_feeds"
    # What put the destination in front of the engine: "report" now,
    # "hot"/"pattern"/"sweep"/"edit" later.
    trigger: str = "report"
    # Trigger-specific snapshot (report reasons, counts) for review embeds.
    context: dict | None = None
    decided_by: str = "system"
    created_at: datetime | None = None
    updated_at: datetime | None = Field(default=None)
