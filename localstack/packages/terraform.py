import platform
from typing import List

from localstack.packages import Package, PackageInstaller
from localstack.packages.core import ExtractDownloadInstaller
from localstack.utils.platform import get_arch

TERRAFORM_VERSION = "1.1.3"
TERRAFORM_URL_TEMPLATE = (
    "https://releases.hashicorp.com/terraform/{version}/terraform_{version}_{os}_{arch}.zip"
)


class TerraformPackage(Package):
    def __init__(self):
        super().__init__("Terraform", "1.1.3")

    def get_versions(self) -> List[str]:
        return ["1.1.3"]

    def _get_installer(self, version: str) -> PackageInstaller:
        return TerraformPackageInstaller("terraform", version)


class TerraformPackageInstaller(ExtractDownloadInstaller):
    def _get_download_url(self) -> str:
        system = platform.system().lower()
        arch = get_arch()
        return TERRAFORM_URL_TEMPLATE.format(version=TERRAFORM_VERSION, os=system, arch=arch)


terraform_package = TerraformPackage()
# TODO: solve this cleanly, violates inheritance rules right now (accessing member not part of the top level interface)
TERRAFORM_BIN = terraform_package.get_installer().get_executable_path()
