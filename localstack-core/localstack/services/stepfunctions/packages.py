from localstack.packages import Package, PackageInstaller
from localstack.packages.core import MavenPackageInstaller
from localstack.packages.java import JavaInstallerMixin

JSONATA_DEFAULT_VERSION = "0.9.7"


class JSONataPackage(Package):
    def __init__(self):
        super().__init__("JSONataLibs", JSONATA_DEFAULT_VERSION)

    def _get_installer(self, version: str) -> PackageInstaller:
        return JSONataPackageInstaller(version)


class JSONataPackageInstaller(JavaInstallerMixin, MavenPackageInstaller):
    def __init__(self, version: str):
        super().__init__(
            f"pkg:maven/com.dashjoin/jsonata@{version}",
        )


jpype_jsonata_package = JSONataPackage()
