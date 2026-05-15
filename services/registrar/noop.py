"""NoOpRegistrar — the LE on-demand path needs no pre-registration.

Self-host deployments wire this so the service-layer ``register`` call
is uniform across backends. ``backend_id`` is None so the persisted doc
carries no foreign key (cf_hostname_id stays None).
"""

from __future__ import annotations

from services.registrar.protocol import HostnameRegistrar, RegistrationResult


class NoOpRegistrar(HostnameRegistrar):
    async def register(
        self, fqdn: str, *, dcv_method: str | None = None
    ) -> RegistrationResult:
        return RegistrationResult(backend_id=None)
