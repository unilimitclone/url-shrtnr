"""Tests for the custom-domain DTOs (PR4 restructure)."""

from __future__ import annotations

from datetime import datetime, timezone

from bson import ObjectId

from schemas.dto.responses.custom_domain import (
    CustomDomainDeleteResponse,
    CustomDomainListResponse,
    CustomDomainResponse,
    DnsRecord,
)
from schemas.enums.domain_status import DomainStatus, VerificationMethod
from schemas.models.custom_domain import CustomDomainDoc


def _doc(**overrides) -> CustomDomainDoc:
    base = {
        "_id": ObjectId(),
        "fqdn": "links.acme.com",
        "owner_id": ObjectId(),
        "status": DomainStatus.PENDING,
        "verification_method": VerificationMethod.CF_HTTP_DCV,
        "verification_token": "tok-123",
        "created_at": datetime(2025, 1, 1, tzinfo=timezone.utc),
        "dns_instructions": [
            {"type": "CNAME", "name": "links.acme.com", "value": "spoo.me"},
            {
                "type": "TXT",
                "name": "_cf-custom-hostname.links.acme.com",
                "value": "abc-uuid",
            },
        ],
        "setup_notes": ["Set DNS-only (grey cloud) if using CF DNS."],
    }
    base.update(overrides)
    return CustomDomainDoc.from_mongo(base)


class TestCustomDomainResponse:
    def test_structured_dns_records(self):
        r = CustomDomainResponse.from_doc(_doc())
        assert len(r.dns_records) == 2
        assert r.dns_records[0].type == "CNAME"
        assert r.dns_records[0].name == "links.acme.com"
        assert r.dns_records[0].value == "spoo.me"
        assert r.dns_records[1].type == "TXT"

    def test_setup_notes_passthrough(self):
        r = CustomDomainResponse.from_doc(_doc())
        assert r.setup_notes == ["Set DNS-only (grey cloud) if using CF DNS."]

    def test_no_verification_token_in_response(self):
        # Internal field — must not be exposed in the public DTO.
        r = CustomDomainResponse.from_doc(_doc())
        assert not hasattr(r, "verification_token")

    def test_no_setup_instructions_in_response(self):
        # Replaced by dns_records + setup_notes.
        r = CustomDomainResponse.from_doc(_doc())
        assert not hasattr(r, "setup_instructions")

    def test_empty_dns_records_when_doc_has_none(self):
        r = CustomDomainResponse.from_doc(_doc(dns_instructions=[]))
        assert r.dns_records == []

    def test_status_and_method_propagate(self):
        r = CustomDomainResponse.from_doc(_doc(status=DomainStatus.ACTIVE))
        assert r.status == DomainStatus.ACTIVE
        assert r.verification_method == VerificationMethod.CF_HTTP_DCV


class TestCustomDomainListResponse:
    def test_paginated_shape(self):
        r = CustomDomainListResponse(
            items=[CustomDomainResponse.from_doc(_doc())],
            page=1,
            pageSize=20,
            total=1,
            hasNext=False,
        )
        # camelCase serialisation via aliases (consistent with UrlListResponse).
        dumped = r.model_dump(by_alias=True)
        assert dumped["pageSize"] == 20
        assert dumped["hasNext"] is False


class TestCustomDomainDeleteResponse:
    def test_no_cascade_zero_count(self):
        r = CustomDomainDeleteResponse(
            id="x", fqdn="links.acme.com", cascade=False, urls_deleted=0
        )
        assert r.cascade is False
        assert r.urls_deleted == 0

    def test_cascade_with_count(self):
        r = CustomDomainDeleteResponse(
            id="x", fqdn="links.acme.com", cascade=True, urls_deleted=42
        )
        assert r.cascade is True
        assert r.urls_deleted == 42


class TestDnsRecord:
    def test_types_constrained_to_known(self):
        # Loose validation by Literal — pydantic raises on unknown
        import pytest
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            DnsRecord(type="MX", name="x", value="y")  # type: ignore[arg-type]
