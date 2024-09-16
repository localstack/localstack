from localstack.packages import Package, PackageInstaller
from localstack.packages.core import MavenPackageInstaller

# https://central.sonatype.com/artifact/software.amazon.event.ruler/event-ruler
EVENT_RULER_VERSION = "1.7.3"
# The dependent jackson.version is defined in the Maven POM File of event-ruler
JACKSON_VERSION = "2.16.2"


class EventRulerPackage(Package):
    def __init__(self):
        super().__init__("EventRulerLibs", EVENT_RULER_VERSION)

    def get_versions(self) -> list[str]:
        return [EVENT_RULER_VERSION]

    def _get_installer(self, version: str) -> PackageInstaller:
        return MavenPackageInstaller(
            f"pkg:maven/software.amazon.event.ruler/event-ruler@{EVENT_RULER_VERSION}",
            f"pkg:maven/com.fasterxml.jackson.core/jackson-annotations@{JACKSON_VERSION}",
            f"pkg:maven/com.fasterxml.jackson.core/jackson-core@{JACKSON_VERSION}",
            f"pkg:maven/com.fasterxml.jackson.core/jackson-databind@{JACKSON_VERSION}",
        )


event_ruler_package = EventRulerPackage()
