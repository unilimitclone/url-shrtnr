"""Shared context builder for the custom meta-tags preview page.

Single source for the ``templates/meta_preview.html`` variable contract —
used by the origin serving branch (routes/redirect_routes.py) and by the
edge KV write-through, which renders the same template offline.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from shared.url_utils import extract_hostname

if TYPE_CHECKING:
    from infrastructure.cache.url_cache import UrlCacheData


def build_preview_context(url: UrlCacheData, *, auto_redirect: bool = True) -> dict:
    """Template context for meta_preview.html.

    ``long_url`` is omitted for block_bots links — a bot-blocked destination
    must never leak to bots. ``auto_redirect`` is disabled for ?bot=1 so
    developers can inspect the page a crawler sees.
    """
    reveal = not url.block_bots
    return {
        "title": url.meta_title,
        "description": url.meta_description,
        "image": url.meta_image,
        "image_width": url.meta_image_width,
        "image_height": url.meta_image_height,
        "color": url.meta_color,
        "short_url": f"https://{url.domain}/{url.alias}",
        "site_name": url.domain,
        "long_url": url.long_url if reveal else None,
        # Withheld alongside long_url: even the hostname of a bot-blocked
        # destination must not enter the template context.
        "dest_host": extract_hostname(url.long_url) if reveal else None,
        "auto_redirect": auto_redirect,
    }
