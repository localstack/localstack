import os
import platform
from typing import List

from localstack.constants import KMS_URL_PATTERN
from localstack.packages import Package, PackageInstaller
from localstack.packages.core import PermissionDownloadInstaller
from localstack.utils.platform import get_arch


class KMSLocalPackage(Package):
    def __init__(self):
        super().__init__("LocalKMS", "latest")

    def get_versions(self) -> List[str]:
        return ["latest"]

    def _get_installer(self, version: str) -> PackageInstaller:
        return KMSLocalPackageInstaller("local-kms", version)


class KMSLocalPackageInstaller(PermissionDownloadInstaller):
    # TODO: this used to be in static libs, fix or remove this
    @staticmethod
    def _get_local_arch():
        return f"{platform.system().lower()}-{get_arch()}"

    def _get_download_url(self) -> str:
        return KMS_URL_PATTERN.replace("<arch>", KMSLocalPackageInstaller._get_local_arch())

    def _get_install_marker_path(self, install_dir: str) -> str:
        return os.path.join(
            install_dir, f"{self.name}.{KMSLocalPackageInstaller._get_local_arch()}.bin"
        )


kms_local_package = KMSLocalPackage()
