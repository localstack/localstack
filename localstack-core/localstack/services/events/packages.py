from localstack.packages import Package, PackageInstaller
from localstack.packages.core import MavenPackageInstaller
from localstack.packages.java import JavaInstallerMixin

# Map of Event Ruler version to Jackson version
# https://central.sonatype.com/artifact/software.amazon.event.ruler/event-ruler
# The dependent jackson.version is defined in the Maven POM File of event-ruler
EVENT_RULER_VERSIONS = {
    "1.7.3": "2.16.2",
}

EVENT_RULER_DEFAULT_VERSION = "1.7.3"


class EventRulerPackage(Package):
    def __init__(self):
        super().__init__("EventRulerLibs", EVENT_RULER_DEFAULT_VERSION)

    def get_versions(self) -> list[str]:
        return list(EVENT_RULER_VERSIONS.keys())

    def _get_installer(self, version: str) -> PackageInstaller:
        return EventRulerPackageInstaller(version)


class EventRulerPackageInstaller(JavaInstallerMixin, MavenPackageInstaller):
    def __init__(self, version: str):
        jackson_version = EVENT_RULER_VERSIONS[version]

        super().__init__(
            f"pkg:maven/software.amazon.event.ruler/event-ruler@{version}",
            f"pkg:maven/com.fasterxml.jackson.core/jackson-annotations@{jackson_version}",
            f"pkg:maven/com.fasterxml.jackson.core/jackson-core@{jackson_version}",
            f"pkg:maven/com.fasterxml.jackson.core/jackson-databind@{jackson_version}",
        )


event_ruler_package = EventRulerPackage()
