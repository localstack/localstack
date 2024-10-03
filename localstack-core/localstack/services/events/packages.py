from localstack.packages import InstallTarget, Package, PackageInstaller
from localstack.packages.core import MavenPackageInstaller
from localstack.packages.java import java_package

# Map of Event Ruler version to Jackson version
# https://central.sonatype.com/artifact/software.amazon.event.ruler/event-ruler
# The dependent jackson.version is defined in the Maven POM File of event-ruler
EVENT_RULER_VERSIONS = {
    "1.7.3": "2.16.2",
}


class EventRulerPackage(Package):
    def __init__(self):
        super().__init__("EventRulerLibs", list(EVENT_RULER_VERSIONS.keys()))

    def get_versions(self) -> list[str]:
        return list(EVENT_RULER_VERSIONS.keys())

    def _get_installer(self, version: str) -> PackageInstaller:
        return EventRulerPackageInstaller(version)


class EventRulerPackageInstaller(MavenPackageInstaller):
    def __init__(self, version: str):
        jackson_version = EVENT_RULER_VERSIONS[version]
        super().__init__(
            f"pkg:maven/software.amazon.event.ruler/event-ruler@{version}",
            f"pkg:maven/com.fasterxml.jackson.core/jackson-annotations@{jackson_version}",
            f"pkg:maven/com.fasterxml.jackson.core/jackson-core@{jackson_version}",
            f"pkg:maven/com.fasterxml.jackson.core/jackson-databind@{jackson_version}",
        )

        self.java_version = "11"

    def _prepare_installation(self, target: InstallTarget) -> None:
        java_package.get_installer(self.java_version).install(target)


event_ruler_package = EventRulerPackage()
