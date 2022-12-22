import os
from functools import lru_cache
from typing import List

from localstack import config
from localstack.packages import GitHubReleaseInstaller, Package, PackageInstaller
from localstack.utils.platform import get_arch, get_os

_KINESIS_MOCK_VERSION = os.environ.get("KINESIS_MOCK_VERSION") or "0.3.1"


class KinesisMockPackage(Package):
    def __init__(self, default_version: str = _KINESIS_MOCK_VERSION):
        super().__init__(name="Kinesis Mock", default_version=default_version)

    @lru_cache
    def _get_installer(self, version: str) -> PackageInstaller:
        return KinesisMockPackageInstaller(version)

    def get_versions(self) -> List[str]:
        return [_KINESIS_MOCK_VERSION]


class KinesisMockPackageInstaller(GitHubReleaseInstaller):
    def __init__(self, version: str):
        super().__init__("kinesis-mock", version, "etspaceman/kinesis-mock")

    def _get_github_asset_name(self):
        arch = get_arch()
        operating_system = get_os()
        if config.is_env_true("KINESIS_MOCK_FORCE_JAVA"):
            # sometimes the static binaries may have problems, and we want to fal back to Java
            bin_file = "kinesis-mock.jar"
        elif arch == "amd64":
            if operating_system == "windows":
                bin_file = "kinesis-mock-mostly-static.exe"
            elif operating_system == "linux":
                bin_file = "kinesis-mock-linux-amd64-static"
            elif operating_system == "osx":
                bin_file = "kinesis-mock-macos-amd64-dynamic"
            else:
                bin_file = "kinesis-mock.jar"
        else:
            bin_file = "kinesis-mock.jar"
        return bin_file


kinesismock_package = KinesisMockPackage()
