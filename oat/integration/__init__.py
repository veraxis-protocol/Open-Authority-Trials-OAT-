"""Production-representative local host/sink integration for OAT method development."""

from oat.integration.host_sink import (
    REFERENCE_ACTION,
    REFERENCE_SINK,
    HostSinkIntegration,
    IntegrationServer,
    new_reference_integration,
)

__all__ = [
    "HostSinkIntegration",
    "IntegrationServer",
    "REFERENCE_ACTION",
    "REFERENCE_SINK",
    "new_reference_integration",
]
