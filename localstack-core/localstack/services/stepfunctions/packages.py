from localstack.packages import Package, PackageInstaller
from localstack.packages.core import MavenPackageInstaller
from localstack.packages.java import JavaInstallerMixin

JSONATA_DEFAULT_VERSION = "0.9.7"


class JSONataPackage(Package):
    def __init__(self):
        super().__init__("JSONataLibs", JSONATA_DEFAULT_VERSION)

        # Match the dynamodb-local JRE version to reduce the LocalStack image size by sharing the same JRE version
        self.java_version = "21"

    def _get_installer(self, version: str) -> PackageInstaller:
        return JSONataPackageInstaller(version)

    def get_versions(self) -> list[str]:
        return [JSONATA_DEFAULT_VERSION]


class JSONataPackageInstaller(JavaInstallerMixin, MavenPackageInstaller):
    def __init__(self, version: str):
        super().__init__(
            f"pkg:maven/com.dashjoin/jsonata@{version}",
        )


jpype_jsonata_package = JSONataPackage()
