"""Tripwire: A/B variants must not go live before safety can see them.

Variants add destinations exactly like geo rules do. Safety enforcement
matches ``dest.host`` or ``dest.secondary_hosts``; a variant host that is
never stamped there matches nothing. The flag does not exist yet; this
test names the work the moment someone adds it and flips it on.
"""

from __future__ import annotations

import inspect

from config import AppSettings
from schemas.models.url import UrlDestination

_FLAGS = ("ab_testing_enabled", "ab_variants_enabled")

_WORK = """
A/B variants were enabled but safety cannot see variant destinations.
Required before shipping them:

  1. pass the variant URLs as ``variants=`` to UrlDestination.for_link at
     every write point (create, update, backfill) so secondary_hosts
     carries them
  2. include variant URLs in link_destination_urls callers (report intake,
     hot screening) so each variant gets its own safety event
  3. stamp existing links: scripts/backfill_url_dest.py
"""


def test_ab_variants_stay_dark_until_enforcement_sees_them():
    settings = AppSettings()
    if not any(getattr(settings, flag, False) for flag in _FLAGS):
        return
    assert "secondary_hosts" in UrlDestination.model_fields, _WORK
    assert "variants" in inspect.signature(UrlDestination.for_link).parameters, _WORK
    stamped = UrlDestination.for_link(
        "https://main.example/", variants=["https://variant.example/b"]
    )
    assert stamped is not None and stamped.secondary_hosts == ["variant.example"], _WORK
