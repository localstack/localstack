from localstack.constants import MAVEN_REPO_URL
from localstack.packages import DownloadInstaller, Package, PackageInstaller
from localstack.packages.api import InstallTarget, MultiPackageInstaller

# https://central.sonatype.com/artifact/software.amazon.event.ruler/event-ruler
EVENT_RULER_VERSION = "1.7.3"
# The dependent jackson.version is defined in the Maven POM File of event-ruler
JACKSON_VERSION = "2.16.2"


class MavenPackageInstaller(DownloadInstaller):
    """LocalStack package installer for Maven dependencies.
    Follows the Maven naming conventions: https://maven.apache.org/guides/mini/guide-naming-conventions.html
    """

    # Example: software.amazon.event.ruler
    group_id: str
    # Example: event-ruler
    artifact_id: str
    # Example version: 1.7.3

    # Optional installation directory to overwrite the default
    install_dir: str | None

    def __init__(self, package_url: str, install_dir: str | None = None):
        """ "The packageURL is easy copy/pastable from the Maven central repository
        Example package_url: pkg:maven/software.amazon.event.ruler/event-ruler@1.7.3
        """
        parts = package_url.split("/")
        self.group_id = parts[1]
        sub_parts = parts[2].split("@")
        self.artifact_id = sub_parts[0]
        version = sub_parts[1]
        super().__init__(self.artifact_id, version)
        self.install_dir = install_dir

    def _get_download_url(self) -> str:
        group_id_path = self.group_id.replace(".", "/")
        return f"{MAVEN_REPO_URL}/{group_id_path}/{self.artifact_id}/{self.version}/{self.artifact_id}-{self.version}.jar"

    def _get_install_dir(self, target: InstallTarget) -> str:
        """Allow to overwrite the default installation directory.
        This enables bundling transitive dependencies into the same directory.
        """
        return self.install_dir or super()._get_install_dir(target)


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
