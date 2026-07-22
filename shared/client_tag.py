"""
X-Spoo-Client header parsing — shared by the logging middleware and routes.

First-party clients identify themselves with ``X-Spoo-Client: <slug>`` or
``<slug>/<version>`` (e.g. ``snap/2.1.0``). Values that do not match the
shape are treated as absent, never rejected — the header is advisory
telemetry, not an auth surface.
"""

from __future__ import annotations

import re

CLIENT_TAG_HEADER = "X-Spoo-Client"

_CLIENT_TAG_RE = re.compile(r"^([a-z0-9_-]{1,32})(?:/([A-Za-z0-9._-]{1,16}))?$")


def parse_client_tag(raw: str | None) -> tuple[str | None, str | None]:
    """Parse an X-Spoo-Client value into ``(client, client_version)``."""
    match = _CLIENT_TAG_RE.match((raw or "").strip())
    if match is None:
        return None, None
    return match.group(1), match.group(2)
