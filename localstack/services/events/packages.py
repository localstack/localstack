from localstack.packages import Package, PackageInstaller
from localstack.packages.api import InstallTarget, MultiPackageInstaller
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
        return EventRulerPackageInstaller()


class EventRulerPackageInstaller(MultiPackageInstaller):
    def __init__(self):
        event_ruler = MavenPackageInstaller(
            f"pkg:maven/software.amazon.event.ruler/event-ruler@{EVENT_RULER_VERSION}"
        )
        event_ruler_dir = event_ruler._get_install_dir(InstallTarget.VAR_LIBS)
        super().__init__(
            "event-ruler",
            EVENT_RULER_VERSION,
            [
                event_ruler,
                MavenPackageInstaller(
                    f"pkg:maven/com.fasterxml.jackson.core/jackson-annotations@{JACKSON_VERSION}",
                    event_ruler_dir,
                ),
                MavenPackageInstaller(
                    f"pkg:maven/com.fasterxml.jackson.core/jackson-core@{JACKSON_VERSION}",
                    event_ruler_dir,
                ),
                MavenPackageInstaller(
                    f"pkg:maven/com.fasterxml.jackson.core/jackson-databind@{JACKSON_VERSION}",
                    event_ruler_dir,
                ),
            ],
        )


event_ruler_package = EventRulerPackage()
