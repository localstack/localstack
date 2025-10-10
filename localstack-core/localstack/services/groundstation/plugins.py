"""Plugin registration for AWS Ground Station service.

This module registers the GroundStationProvider with LocalStack's service framework.
"""

from localstack.packages import Package, package
from localstack.services.plugins import ServicePlugin


# No external package dependencies for Ground Station service
@package(name="groundstation")
def groundstation_package() -> Package:
    """Ground Station service package (no external dependencies)."""
    from localstack.packages.core import SystemPackage

    return SystemPackage()


class GroundStationPlugin(ServicePlugin):
    """Plugin for AWS Ground Station service."""

    name = "groundstation"

    def load(self):
        """Load the Ground Station service provider."""
        from .provider import GroundStationProvider

        return GroundStationProvider()
