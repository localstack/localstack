import platform
from typing import List

from localstack.packages import Package, PackageInstaller
from localstack.packages.core import PermissionDownloadInstaller
from localstack.utils.platform import get_arch

KMS_URL_PATTERN = "https://s3-eu-west-2.amazonaws.com/local-kms/3/local-kms_<arch>.bin"


class KMSLocalPackage(Package):
    def __init__(self):
        super().__init__("LocalKMS", "latest")

    def get_versions(self) -> List[str]:
        return ["latest"]

    def _get_installer(self, version: str) -> PackageInstaller:
        return KMSLocalPackageInstaller("local-kms", version)


class KMSLocalPackageInstaller(PermissionDownloadInstaller):
    def _get_download_url(self) -> str:
        return KMS_URL_PATTERN.replace("<arch>", f"{platform.system().lower()}-{get_arch()}")


kms_local_package = KMSLocalPackage()
