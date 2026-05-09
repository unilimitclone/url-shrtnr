"""Unit tests for TxtChallengeVerifier."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import dns.resolver
import pytest

from services.verifiers.txt_challenge_verifier import TxtChallengeVerifier


def _txt_answer(*records: bytes | list[bytes]) -> list[MagicMock]:
    """Build a fake dnspython TXT rrset.

    Each record can be a single bytes value or a list of byte chunks (TXT
    splits >255-byte payloads into multiple chunks per record on the wire).
    """
    rrs = []
    for r in records:
        rdata = MagicMock()
        rdata.strings = r if isinstance(r, list) else [r]
        rrs.append(rdata)
    return rrs


class TestTxtChallengeVerifier:
    @pytest.mark.asyncio
    async def test_verified_when_token_matches(self):
        v = TxtChallengeVerifier()
        with patch(
            "services.verifiers.txt_challenge_verifier.dns.asyncresolver.resolve",
            new=AsyncMock(return_value=_txt_answer(b"abc-123")),
        ):
            r = await v.verify("acme.com", token="abc-123")
        assert r.verified is True

    @pytest.mark.asyncio
    async def test_verified_when_token_in_one_of_many(self):
        v = TxtChallengeVerifier()
        with patch(
            "services.verifiers.txt_challenge_verifier.dns.asyncresolver.resolve",
            new=AsyncMock(
                return_value=_txt_answer(b"v=spf1 ...", b"abc-123", b"some-other-ack")
            ),
        ):
            r = await v.verify("acme.com", token="abc-123")
        assert r.verified is True

    @pytest.mark.asyncio
    async def test_handles_multi_chunk_txt_concatenation(self):
        # TXT records over 255 bytes get split into chunks; verifier must join.
        v = TxtChallengeVerifier()
        with patch(
            "services.verifiers.txt_challenge_verifier.dns.asyncresolver.resolve",
            new=AsyncMock(return_value=_txt_answer([b"abc-", b"123"])),
        ):
            r = await v.verify("acme.com", token="abc-123")
        assert r.verified is True

    @pytest.mark.asyncio
    async def test_token_missing_raises_internal_error(self):
        # Missing token = programmer error from the orchestrator. Should
        # fail closed with an obvious diagnostic.
        v = TxtChallengeVerifier()
        r = await v.verify("acme.com", token=None)
        assert r.verified is False
        assert "internal" in r.reason.lower()

    @pytest.mark.asyncio
    async def test_nxdomain_includes_setup_hint(self):
        v = TxtChallengeVerifier()
        with patch(
            "services.verifiers.txt_challenge_verifier.dns.asyncresolver.resolve",
            new=AsyncMock(side_effect=dns.resolver.NXDOMAIN()),
        ):
            r = await v.verify("acme.com", token="abc-123")
        assert r.verified is False
        assert "_spoo-challenge.acme.com" in r.reason
        assert "abc-123" in r.reason

    @pytest.mark.asyncio
    async def test_mismatch_lists_expected_token(self):
        v = TxtChallengeVerifier()
        with patch(
            "services.verifiers.txt_challenge_verifier.dns.asyncresolver.resolve",
            new=AsyncMock(return_value=_txt_answer(b"wrong-token")),
        ):
            r = await v.verify("acme.com", token="abc-123")
        assert r.verified is False
        assert "abc-123" in r.reason
