"""Tests for bot detection — the pre-emit blocking decision in particular."""

from __future__ import annotations

from services.click.bot_detection import is_bot_request, should_block_bot
from tests.factories import make_url_cache

BOT_UA = "Googlebot/2.1 (+http://www.google.com/bot.html)"
BROWSER_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0 Safari/537.36"
)


class TestIsBotRequest:
    def test_known_bot(self):
        assert is_bot_request(BOT_UA) is True

    def test_browser(self):
        assert is_bot_request(BROWSER_UA) is False

    def test_empty_ua_is_unclassifiable(self):
        assert is_bot_request("") is False


class TestShouldBlockBot:
    def test_v1_bot_on_blocking_url_is_blocked(self):
        url = make_url_cache(schema_version="v1", block_bots=True)
        assert should_block_bot("GET", BOT_UA, url, "v1") is True

    def test_emoji_bot_on_blocking_url_is_blocked(self):
        url = make_url_cache(schema_version="v1", block_bots=True)
        assert should_block_bot("GET", BOT_UA, url, "emoji") is True

    def test_v2_never_blocks_the_redirect(self):
        """v2 bot handling is analytics-skip in the pipeline, not a 403."""
        url = make_url_cache(schema_version="v2", block_bots=True)
        assert should_block_bot("GET", BOT_UA, url, "v2") is False

    def test_block_bots_off_never_blocks(self):
        url = make_url_cache(schema_version="v1", block_bots=False)
        assert should_block_bot("GET", BOT_UA, url, "v1") is False

    def test_human_ua_never_blocks(self):
        url = make_url_cache(schema_version="v1", block_bots=True)
        assert should_block_bot("GET", BROWSER_UA, url, "v1") is False

    def test_empty_ua_falls_through_to_pipeline(self):
        """Unclassifiable UA → pipeline's ValidationError path decides."""
        url = make_url_cache(schema_version="v1", block_bots=True)
        assert should_block_bot("GET", "", url, "v1") is False

    def test_head_and_options_are_exempt(self):
        url = make_url_cache(schema_version="v1", block_bots=True)
        assert should_block_bot("HEAD", BOT_UA, url, "v1") is False
        assert should_block_bot("OPTIONS", BOT_UA, url, "v1") is False
