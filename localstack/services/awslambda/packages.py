import os
import stat
from typing import List

from localstack.packages import InstallTarget, Package, PackageInstaller
from localstack.services.install import log_install_msg
from localstack.utils.http import download
from localstack.utils.platform import get_arch

LAMBDA_RUNTIME_INIT_URL = "https://github.com/localstack/lambda-runtime-init/releases/download/{version}/aws-lambda-rie-{arch}"

# TODO: talk with Alex, move this really to constants?
LAMBDA_RUNTIME_DEFAULT_VERSION = "v0.1.4-pre"


class AwsLambdaRuntimePackage(Package):
    def __init__(self, default_version: str = LAMBDA_RUNTIME_DEFAULT_VERSION):
        super().__init__(name="AwsLambda", default_version=default_version)

    def get_versions(self) -> List[str]:
        return ["v0.1.4-pre", "v0.1.1-pre", "v0.1-pre"]

    def _get_installer(self, version: str) -> PackageInstaller:
        return AwsLambdaRuntimePackageInstaller(name="awslambda-runtime", version=version)


class AwsLambdaRuntimePackageInstaller(PackageInstaller):
    def _get_install_marker_path(self, install_dir: str) -> str:
        return os.path.join(install_dir, "aws-lambda-rie")

    def _install(self, target: InstallTarget) -> None:
        install_location = self._get_install_marker_path(self._get_install_dir(target))
        if os.path.isfile(install_location):
            return
        log_install_msg("Installing lambda runtime")
        arch = get_arch()
        arch = "x86_64" if arch == "amd64" else arch
        download_url = LAMBDA_RUNTIME_INIT_URL.format(version=self.version, arch=arch)
        download(download_url, install_location)
        st = os.stat(install_location)
        os.chmod(install_location, mode=st.st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


awslambda_runtime_package = AwsLambdaRuntimePackage()
