from typing import List

from localstack.packages import DownloadInstaller, Package, PackageInstaller


class CloudformationPackage(Package):
    def __init__(self):
        super().__init__("Clouformation", "latest")

    def get_versions(self) -> List[str]:
        return ["latest"]

    def _get_installer(self, version: str) -> PackageInstaller:
        return CloudformationPackageInstaller("cloudformation", version)


class CloudformationPackageInstaller(DownloadInstaller):
    def _get_download_url(self) -> str:
        return "https://raw.githubusercontent.com/LukeMizuhashi/cfn-response/master/index.js"


cloudformation_package = CloudformationPackage()
