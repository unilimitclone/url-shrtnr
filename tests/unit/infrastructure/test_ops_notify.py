"""Unit tests for DiscordOpsNotifier — delivery semantics, channel
routing, and embed formatting (owned here, not by the calling services)."""

from unittest.mock import AsyncMock, MagicMock

from infrastructure.ops_notify import DiscordOpsNotifier

_CONTACT_URL = "https://discord.com/api/webhooks/123/contact"
_REPORT_URL = "https://discord.com/api/webhooks/123/report"


def _make(contact_url=_CONTACT_URL, report_url=_REPORT_URL, status_code=204):
    http = MagicMock()
    resp = MagicMock(status_code=status_code, text="Bad Request")
    http.post = AsyncMock(return_value=resp)
    return DiscordOpsNotifier(contact_url, report_url, http), http


class TestDelivery:
    async def test_returns_true_on_204(self):
        notifier, _ = _make(status_code=204)
        assert await notifier.contact_message("a@b.c", "hi") is True

    async def test_returns_true_on_200(self):
        notifier, _ = _make(status_code=200)
        assert await notifier.contact_message("a@b.c", "hi") is True

    async def test_returns_false_on_error_status(self):
        notifier, _ = _make(status_code=400)
        assert await notifier.contact_message("a@b.c", "hi") is False

    async def test_returns_false_when_channel_unconfigured(self):
        notifier, http = _make(contact_url="")
        assert await notifier.contact_message("a@b.c", "hi") is False
        http.post.assert_not_awaited()

    async def test_returns_false_on_exception(self):
        notifier, http = _make()
        http.post = AsyncMock(side_effect=Exception("network error"))
        assert await notifier.contact_message("a@b.c", "hi") is False


class TestChannelRouting:
    async def test_contact_message_goes_to_contact_channel(self):
        notifier, http = _make()
        await notifier.contact_message("a@b.c", "hi")
        assert http.post.call_args[0][0] == _CONTACT_URL

    async def test_url_report_goes_to_report_channel(self):
        notifier, http = _make()
        await notifier.url_report("abc123", "spam", "1.2.3.4", "https://spoo.me/")
        assert http.post.call_args[0][0] == _REPORT_URL

    async def test_unconfigured_report_channel_does_not_leak_to_contact(self):
        notifier, http = _make(report_url="")
        assert (
            await notifier.url_report("abc123", "spam", "1.2.3.4", "https://spoo.me/")
            is False
        )
        http.post.assert_not_awaited()


class TestContactEmbed:
    async def test_embed_contains_email_and_message(self):
        notifier, http = _make()
        await notifier.contact_message("user@example.com", "My message")
        embed = http.post.call_args.kwargs["json"]["embeds"][0]
        field_names = [f["name"] for f in embed["fields"]]
        assert "Email" in field_names
        assert "Message" in field_names
        assert embed["fields"][0]["value"] == "```user@example.com```"
        assert embed["fields"][1]["value"] == "```My message```"

    async def test_embed_title_is_new_contact_message(self):
        notifier, http = _make()
        await notifier.contact_message("user@example.com", "Hello")
        embed = http.post.call_args.kwargs["json"]["embeds"][0]
        assert "Contact" in embed["title"]
        assert embed["footer"]["text"] == "spoo-me"


class TestUrlReportEmbed:
    async def test_embed_contains_short_code_reason_ip(self):
        notifier, http = _make()
        await notifier.url_report("abc123", "phishing", "1.2.3.4", "https://spoo.me/")
        embed = http.post.call_args.kwargs["json"]["embeds"][0]
        field_names = [f["name"] for f in embed["fields"]]
        assert "Short Code" in field_names
        assert "Reason" in field_names
        assert "IP Address" in field_names

    async def test_embed_title_contains_short_code(self):
        notifier, http = _make()
        await notifier.url_report("abc123", "spam", "1.2.3.4", "https://spoo.me/")
        embed = http.post.call_args.kwargs["json"]["embeds"][0]
        assert "abc123" in embed["title"]

    async def test_embed_url_points_to_stats_page(self):
        notifier, http = _make()
        await notifier.url_report("abc123", "spam", "1.2.3.4", "https://spoo.me/")
        embed = http.post.call_args.kwargs["json"]["embeds"][0]
        assert embed["url"] == "https://spoo.me/stats/abc123"
