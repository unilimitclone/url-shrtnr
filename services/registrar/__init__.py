"""Hostname registration plane.

Separate from verifier (proof-of-ownership check) and edge provisioner
(cert eviction) because the act of *announcing* a hostname to the edge
platform is a distinct lifecycle event with its own failure modes —
some backends (CF SaaS) require it; others (LE on-demand) don't.
"""

from services.registrar.noop import NoOpRegistrar
from services.registrar.protocol import HostnameRegistrar, RegistrationResult

__all__ = ["HostnameRegistrar", "NoOpRegistrar", "RegistrationResult"]
