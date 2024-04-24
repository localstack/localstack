import os
from functools import lru_cache
from typing import List

from localstack.packages import Package, PackageInstaller
from localstack.packages.core import NodePackageInstaller

DEFAULT_CDKLOCAL_VERSION = "2.18.0"


class CdkLocalPackage(Package):
    def __init__(self, default_version: str = DEFAULT_CDKLOCAL_VERSION):
        super().__init__(name="CDK Local", default_version=default_version)

    @lru_cache
    def _get_installer(self, version: str) -> PackageInstaller:
        return CdkLocalInstaller(version)

    def get_versions(self) -> List[str]:
        return [DEFAULT_CDKLOCAL_VERSION]


class CdkLocalInstaller(NodePackageInstaller):
    def __init__(self, version: str):
        package_name = "aws-cdk-local"
        super().__init__(
            package_name=package_name,
            package_spec=[f"{package_name}@{version}", "aws-cdk"],
            version=version,
        )

    def _get_install_marker_path(self, install_dir: str) -> str:
        return os.path.join(
            install_dir,
            "node_modules",
            self.package_name,
            "bin",
            "cdklocal",
        )


cdklocal_package = CdkLocalPackage()
