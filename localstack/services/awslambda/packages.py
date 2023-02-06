import os
import platform
import stat
from typing import List

from localstack.packages import DownloadInstaller, InstallTarget, Package, PackageInstaller
from localstack.packages.core import ArchiveDownloadAndExtractInstaller, SystemNotSupportedException
from localstack.utils.platform import get_arch

LAMBDA_RUNTIME_INIT_URL = "https://github.com/localstack/lambda-runtime-init/releases/download/{version}/aws-lambda-rie-{arch}"

LAMBDA_RUNTIME_DEFAULT_VERSION = "v0.1.11-pre"

# GO Lambda runtime
GO_RUNTIME_VERSION = "0.4.0"
GO_RUNTIME_DOWNLOAD_URL_TEMPLATE = "https://github.com/localstack/awslamba-go-runtime/releases/download/v{version}/awslamba-go-runtime-{version}-{os}-{arch}.tar.gz"


class AWSLambdaRuntimePackage(Package):
    def __init__(self, default_version: str = LAMBDA_RUNTIME_DEFAULT_VERSION):
        super().__init__(name="AwsLambda", default_version=default_version)

    def get_versions(self) -> List[str]:
        return [LAMBDA_RUNTIME_DEFAULT_VERSION]

    def _get_installer(self, version: str) -> PackageInstaller:
        return AWSLambdaRuntimePackageInstaller(name="awslambda-runtime", version=version)


class AWSLambdaRuntimePackageInstaller(DownloadInstaller):
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


class AWSLambdaGoRuntimePackage(Package):
    def __init__(self, default_version: str = GO_RUNTIME_VERSION):
        super().__init__(name="AwsLambdaGo", default_version=default_version)

    def get_versions(self) -> List[str]:
        return [GO_RUNTIME_VERSION]

    def _get_installer(self, version: str) -> PackageInstaller:
        return AWSLambdaGoRuntimePackageInstaller(name="awslamba-go-runtime", version=version)


class AWSLambdaGoRuntimePackageInstaller(ArchiveDownloadAndExtractInstaller):
    def _get_download_url(self) -> str:
        system = platform.system().lower()
        arch = get_arch()

        if system not in ["linux"]:
            raise SystemNotSupportedException(f"Unsupported os {system} for awslambda-go-runtime")
        if arch not in ["amd64", "arm64"]:
            raise SystemNotSupportedException(f"Unsupported arch {arch} for awslambda-go-runtime")

        return GO_RUNTIME_DOWNLOAD_URL_TEMPLATE.format(
            version=GO_RUNTIME_VERSION,
            os=system,
            arch=arch,
        )

    def _get_install_marker_path(self, install_dir: str) -> str:
        return os.path.join(install_dir, "aws-lambda-mock")

    def _install(self, target: InstallTarget) -> None:
        super()._install(target)

        install_dir = self._get_install_dir(target)
        install_location = self._get_install_marker_path(install_dir)
        st = os.stat(install_location)
        os.chmod(install_location, st.st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

        go_lambda_mockserver = os.path.join(install_dir, "mockserver")
        st = os.stat(go_lambda_mockserver)
        os.chmod(go_lambda_mockserver, st.st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


# version of the Maven dependency with Java utility code
LOCALSTACK_MAVEN_VERSION = "0.2.21"
MAVEN_REPO_URL = "https://repo1.maven.org/maven2"
URL_LOCALSTACK_FAT_JAR = (
    "{mvn_repo}/cloud/localstack/localstack-utils/{ver}/localstack-utils-{ver}-fat.jar"
)


class AWSLambdaJavaPackage(Package):
    def __init__(self):
        super().__init__("LambdaJavaLibs", "0.2.22")

    def get_versions(self) -> List[str]:
        return ["0.2.22", "0.2.21"]

    def _get_installer(self, version: str) -> PackageInstaller:
        return AWSLambdaJavaPackageInstaller("lambda-java-libs", version)


class AWSLambdaJavaPackageInstaller(DownloadInstaller):
    def _get_download_url(self) -> str:
        return URL_LOCALSTACK_FAT_JAR.format(ver=self.version, mvn_repo=MAVEN_REPO_URL)


awslambda_runtime_package = AWSLambdaRuntimePackage()
awslambda_go_runtime_package = AWSLambdaGoRuntimePackage()
lambda_java_libs_package = AWSLambdaJavaPackage()
