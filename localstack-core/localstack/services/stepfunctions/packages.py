from localstack.packages import Package, PackageInstaller
from localstack.packages.core import MavenPackageInstaller
from localstack.packages.java import JavaInstallerMixin

JSONATA_DEFAULT_VERSION = "0.9.7"
JACKSON_DEFAULT_VERSION = "2.16.2"

JSONATA_JACKSON_VERSION_STORE = {JSONATA_DEFAULT_VERSION: JACKSON_DEFAULT_VERSION}


class JSONataPackage(Package):
    def __init__(self):
        super().__init__("JSONataLibs", JSONATA_DEFAULT_VERSION)

        # Match the dynamodb-local JRE version to reduce the LocalStack image size by sharing the same JRE version
        self.java_version = "21"

    def get_versions(self) -> list[str]:
        return list(JSONATA_JACKSON_VERSION_STORE.keys())

    def _get_installer(self, version: str) -> PackageInstaller:
        return JSONataPackageInstaller(version)


class JSONataPackageInstaller(JavaInstallerMixin, MavenPackageInstaller):
    def __init__(self, version: str):
        jackson_version = JSONATA_JACKSON_VERSION_STORE[version]
        super().__init__(
            f"pkg:maven/com.dashjoin/jsonata@{version}",
            # jackson-databind is imported in jsonata.py as "from com.fasterxml.jackson.databind import ObjectMapper"
            # jackson-annotations and jackson-core are dependencies of jackson-databind:
            # https://central.sonatype.com/artifact/com.fasterxml.jackson.core/jackson-databind/dependencies
            f"pkg:maven/com.fasterxml.jackson.core/jackson-core@{jackson_version}",
            f"pkg:maven/com.fasterxml.jackson.core/jackson-annotations@{jackson_version}",
            f"pkg:maven/com.fasterxml.jackson.core/jackson-databind@{jackson_version}",
        )


jpype_jsonata_package = JSONataPackage()
