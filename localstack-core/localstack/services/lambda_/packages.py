"""Package installers for external Lambda dependencies."""

import os
import stat
from functools import cache
from pathlib import Path
from typing import List

from localstack import config
from localstack.packages import DownloadInstaller, InstallTarget, Package, PackageInstaller
from localstack.utils.platform import get_arch

"""Customized LocalStack version of the AWS Lambda Runtime Interface Emulator (RIE).
https://github.com/localstack/lambda-runtime-init/blob/localstack/README-LOCALSTACK.md
"""
LAMBDA_RUNTIME_DEFAULT_VERSION = "v0.1.30-pre"
LAMBDA_RUNTIME_VERSION = config.LAMBDA_INIT_RELEASE_VERSION or LAMBDA_RUNTIME_DEFAULT_VERSION
LAMBDA_RUNTIME_INIT_URL = "https://github.com/localstack/lambda-runtime-init/releases/download/{version}/aws-lambda-rie-{arch}"

"""Unmaintained Java utilities and JUnit integration for LocalStack released to Maven Central.
https://github.com/localstack/localstack-java-utils
We recommend the Testcontainers LocalStack Java module as an alternative:
https://java.testcontainers.org/modules/localstack/
"""
LOCALSTACK_MAVEN_VERSION = "0.2.21"
MAVEN_REPO_URL = "https://repo1.maven.org/maven2"
URL_LOCALSTACK_FAT_JAR = (
    "{mvn_repo}/cloud/localstack/localstack-utils/{ver}/localstack-utils-{ver}-fat.jar"
)


class LambdaRuntimePackage(Package):
    """Golang binary containing the lambda-runtime-init."""

    def __init__(self, default_version: str = LAMBDA_RUNTIME_VERSION):
        super().__init__(name="Lambda", default_version=default_version)

    def get_versions(self) -> List[str]:
        return [LAMBDA_RUNTIME_VERSION]

    def _get_installer(self, version: str) -> PackageInstaller:
        return LambdaRuntimePackageInstaller(name="lambda-runtime", version=version)


class LambdaRuntimePackageInstaller(DownloadInstaller):
    """Installer for the lambda-runtime-init Golang binary."""

    # TODO: Architecture should ideally be configurable in the installer for proper cross-architecture support.
    # We currently hope the native binary works within emulated containers.
    def _get_arch(self):
        arch = get_arch()
        return "x86_64" if arch == "amd64" else arch

    def _get_download_url(self) -> str:
        arch = self._get_arch()
        return LAMBDA_RUNTIME_INIT_URL.format(version=self.version, arch=arch)

    def _get_install_dir(self, target: InstallTarget) -> str:
        install_dir = super()._get_install_dir(target)
        arch = self._get_arch()
        return os.path.join(install_dir, arch)

    def _get_install_marker_path(self, install_dir: str) -> str:
        return os.path.join(install_dir, "var", "rapid", "init")

    def _install(self, target: InstallTarget) -> None:
        super()._install(target)
        install_location = self.get_executable_path()
        st = os.stat(install_location)
        os.chmod(install_location, mode=st.st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


# TODO: replace usage in LocalStack tests with locally built Java jar and remove this unmaintained dependency.
class LambdaJavaPackage(Package):
    def __init__(self):
        super().__init__("LambdaJavaLibs", "0.2.22")

    def get_versions(self) -> List[str]:
        return ["0.2.22", "0.2.21"]

    def _get_installer(self, version: str) -> PackageInstaller:
        return LambdaJavaPackageInstaller("lambda-java-libs", version)


class LambdaJavaPackageInstaller(DownloadInstaller):
    def _get_download_url(self) -> str:
        return URL_LOCALSTACK_FAT_JAR.format(ver=self.version, mvn_repo=MAVEN_REPO_URL)


lambda_runtime_package = LambdaRuntimePackage()
lambda_java_libs_package = LambdaJavaPackage()


# TODO: handle architecture-specific installer and caching because we currently assume that the lambda-runtime-init
#   Golang binary is cross-architecture compatible.
@cache
def get_runtime_client_path() -> Path:
    installer = lambda_runtime_package.get_installer()
    installer.install()
    return Path(installer.get_installed_dir())
