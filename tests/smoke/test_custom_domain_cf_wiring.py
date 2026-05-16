"""Smoke test: wire_services picks the right backend based on CF config.

CF zone id set ⇒ same CfSaasBackend instance fills all three protocol
slots (verifiers, edge_provisioner, registrar). Unset ⇒ DNS verifiers
+ Caddy provisioner + NoOp registrar.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from config import AppSettings, CustomDomainSettings
from dependencies.wiring import wire_services
from schemas.enums.domain_status import VerificationMethod
from services.cf_saas_backend import CfSaasBackend
from services.edge_provisioner import CaddyAskProvisioner
from services.registrar import NoOpRegistrar
from services.verifiers import ARecordVerifier, CnameVerifier, TxtChallengeVerifier


def _wire(custom_domains: CustomDomainSettings):
    settings = AppSettings()
    settings.custom_domains = custom_domains
    app = MagicMock()
    app.state.db = {  # dict subscript so wiring db["..."] works on a MagicMock-free path
        "urlsV2": MagicMock(name="urlsV2"),
        "urls": MagicMock(name="urls"),
        "emojis": MagicMock(name="emojis"),
        "clicks": MagicMock(name="clicks"),
        "users": MagicMock(name="users"),
        "verification-tokens": MagicMock(name="tokens"),
        "api-keys": MagicMock(name="apikeys"),
        "blocked-urls": MagicMock(name="blocked-urls"),
        "app-grants": MagicMock(name="app-grants"),
        "feature_flags": MagicMock(name="feature_flags"),
        "custom_domains": MagicMock(name="custom_domains"),
        "blocked_domains": MagicMock(name="blocked_domains"),
    }
    app.state.http_client = MagicMock()
    app.state.geoip = MagicMock()
    app.state.email_provider = MagicMock()
    redis_client = None
    wire_services(app, settings, redis_client)
    return app


class TestSelfHostPathWhenCfNotConfigured:
    def test_dns_verifiers_wired_for_each_legacy_method(self):
        app = _wire(CustomDomainSettings(enabled=True))
        svc = app.state.custom_domain_service
        assert isinstance(svc._verifiers[VerificationMethod.CNAME], CnameVerifier)
        assert isinstance(svc._verifiers[VerificationMethod.A_RECORD], ARecordVerifier)
        assert isinstance(
            svc._verifiers[VerificationMethod.TXT_CHALLENGE], TxtChallengeVerifier
        )

    def test_caddy_provisioner_and_noop_registrar(self):
        app = _wire(CustomDomainSettings(enabled=True))
        svc = app.state.custom_domain_service
        assert isinstance(svc._edge, CaddyAskProvisioner)
        assert isinstance(svc._registrar, NoOpRegistrar)

    def test_cf_methods_absent_in_self_host_path(self):
        app = _wire(CustomDomainSettings(enabled=True))
        svc = app.state.custom_domain_service
        assert VerificationMethod.CF_DELEGATED_DCV not in svc._verifiers
        assert VerificationMethod.CF_HTTP_DCV not in svc._verifiers


class TestCfSaasPathWhenCfConfigured:
    def test_single_cf_backend_fills_three_slots(self):
        app = _wire(
            CustomDomainSettings(
                enabled=True,
                cf_zone_id="zone1",
                cf_api_token="tok",
                cf_dcv_delegation_target="abc.dcv.cloudflare.com",
            )
        )
        svc = app.state.custom_domain_service
        # Same instance in all three slots — wiring contract.
        assert isinstance(svc._edge, CfSaasBackend)
        assert isinstance(svc._registrar, CfSaasBackend)
        assert svc._edge is svc._registrar
        assert svc._verifiers[VerificationMethod.CF_DELEGATED_DCV] is svc._edge
        assert svc._verifiers[VerificationMethod.CF_HTTP_DCV] is svc._edge

    def test_dns_verifiers_absent_in_cf_path(self):
        app = _wire(
            CustomDomainSettings(
                enabled=True,
                cf_zone_id="zone1",
                cf_api_token="tok",
                cf_dcv_delegation_target="abc.dcv.cloudflare.com",
            )
        )
        svc = app.state.custom_domain_service
        assert VerificationMethod.CNAME not in svc._verifiers
        assert VerificationMethod.A_RECORD not in svc._verifiers
        assert VerificationMethod.TXT_CHALLENGE not in svc._verifiers


class TestCfConfigValidation:
    def test_cf_zone_id_without_token_fails_at_settings_load(self):
        with pytest.raises(ValueError, match="cf_api_token"):
            CustomDomainSettings(cf_zone_id="zone1")
