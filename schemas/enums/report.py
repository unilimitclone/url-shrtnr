"""Report intake enums — the reporter-supplied triage hints.

Both values are stored VERBATIM on the per-code report document
(``reasons`` / ``vectors`` $addToSet arrays). They are triage hints for
the abuse funnel, never inputs to automated action — assessed harm tiers
live in the url-safety architecture, not here.
"""

from enum import Enum


class ReportReason(str, Enum):
    """Reporter-claimed reason, aligned with the safety framework's harm
    tiers so intake slots into the funnel without a translation layer."""

    PHISHING = "phishing"
    MALWARE = "malware"
    SPAM = "spam"
    ILLEGAL_CONTENT = "illegal_content"
    OTHER = "other"


class ReportVector(str, Enum):
    """How the link reached the reporter — the delivery-vector hint the
    451 page's scam-awareness story needs."""

    SMS = "sms"
    EMAIL = "email"
    DM = "dm"
    SOCIAL = "social"
    WEB = "web"
    OTHER = "other"
