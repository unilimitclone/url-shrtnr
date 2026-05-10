"""Unit tests for shared/url_utils.py — extract_hostname + extract_fqdn + normalise_fqdn."""

import pytest

from shared.url_utils import extract_fqdn, extract_hostname, normalise_fqdn


class TestExtractHostname:
    def test_returns_hostname_from_full_url(self):
        assert extract_hostname("https://spoo.me/path") == "spoo.me"

    def test_returns_hostname_with_port(self):
        # urlparse strips the port from .hostname
        assert extract_hostname("http://localhost:8000/abc") == "localhost"

    def test_returns_none_for_empty(self):
        assert extract_hostname(None) is None
        assert extract_hostname("") is None

    def test_returns_none_for_unparseable(self):
        # urllib's urlparse is forgiving but a string with no scheme and no
        # netloc structure resolves to ``hostname=None``.
        assert extract_hostname("not a url at all") is None


class TestExtractFqdn:
    def test_lowercases(self):
        assert extract_fqdn("HTTPS://SPOO.ME/abc") == "spoo.me"

    def test_strips_trailing_dot(self):
        # Fully qualified DNS notation includes a trailing dot for the root.
        assert extract_fqdn("https://spoo.me./abc") == "spoo.me"

    def test_strips_port(self):
        assert extract_fqdn("https://spoo.me:8443/x") == "spoo.me"

    def test_handles_subdomain(self):
        assert extract_fqdn("https://links.acme.com/x") == "links.acme.com"

    def test_self_hoster_url(self):
        assert extract_fqdn("https://my.shortener.dev") == "my.shortener.dev"

    def test_falls_back_to_localhost_for_no_host(self):
        # Defensive fallback for callers fed user-supplied URLs that lack
        # a parseable host (raw paths, garbage strings).
        assert extract_fqdn("") == "localhost"
        assert extract_fqdn("not-a-url") == "localhost"

    def test_idempotent(self):
        # Two calls with equivalent inputs return identical strings — needed
        # so the cache key, the seeded custom_domains row, and the request
        # middleware all agree on the canonical form.
        assert extract_fqdn("HTTPS://Spoo.Me./") == extract_fqdn("https://spoo.me")


class TestNormaliseFqdn:
    @pytest.mark.parametrize(
        "value, expected",
        [
            ("links.acme.com", "links.acme.com"),
            ("LINKS.ACME.COM", "links.acme.com"),
            ("  links.acme.com  ", "links.acme.com"),
            ("links.acme.com.", "links.acme.com"),
            ("acme.co", "acme.co"),
            # Punycode TLD (encoded `.中国`) — required for IDN custom domains.
            ("links.xn--fiqs8s", "links.xn--fiqs8s"),
            # Multi-level subdomain
            ("a.b.c.example.com", "a.b.c.example.com"),
        ],
    )
    def test_accepts_valid_inputs(self, value, expected):
        assert normalise_fqdn(value) == expected

    @pytest.mark.parametrize(
        "value",
        [
            None,
            "",
            "   ",
            "no_underscores_allowed.com",
            "-leading-hyphen.com",
            "trailing-hyphen-.com",
            "single-label",
            "two..consecutive.dots.com",
            "evil<script>.com",
            "evil`backtick.com",
            "evil\\backslash.com",
            "evil\x00null.com",
            "a" * 64 + ".com",  # label > 63 chars
            "a" * 254 + ".com",  # total > 253 chars
        ],
    )
    def test_rejects_invalid_inputs(self, value):
        with pytest.raises(ValueError):
            normalise_fqdn(value)
