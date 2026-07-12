"""
Aliases that may never be issued as short codes on the default domain.

Every top-level path the frontend serves or is planned to serve, plus
infrastructure names (health, static, robots, …). A short code equal to
one of these would be shadowed by the edge path dispatch — the link
would exist in the database but never resolve. Custom-domain namespaces
carry no frontend paths, so the check does not apply there.

Matching is case-insensitive: URL paths are case-sensitive so ``About``
would not literally shadow ``/about``, but near-miss aliases of product
surfaces are phishing bait with no legitimate value.
"""

from __future__ import annotations

RESERVED_ALIASES: frozenset[str] = frozenset(
    {
        "about",
        "api",
        "apps",
        "auth",
        "billing",
        "blog",
        "callback",
        "changelog",
        "contact",
        "dashboard",
        "discord",
        "docs",
        "domains",
        "emoji",
        "error",
        "export",
        "favicon",
        "features",
        "forgot-password",
        "github",
        "health",
        "help",
        "home",
        "humans",
        "icon",
        "images",
        "keys",
        "legal",
        "links",
        "login",
        "logout",
        "metric",
        "oauth",
        "onboarding",
        "pricing",
        "privacy",
        "privacy-policy",
        "profile",
        "profile-pictures",
        "public",
        "register",
        "relay",
        "report",
        "reset",
        "result",
        "robots",
        "security",
        "settings",
        "signin",
        "signup",
        "sitemap",
        "statistics",
        "stats",
        "static",
        "terms",
        "terms-of-service",
        "testimonials",
        "tos",
        "twitter",
        "verify",
        "_next",
        "_not-found",
        "_error",
        "_gone",
    }
)


def is_reserved_alias(alias: str) -> bool:
    """Return True when *alias* may never be issued as a short code."""
    return alias.lower() in RESERVED_ALIASES
