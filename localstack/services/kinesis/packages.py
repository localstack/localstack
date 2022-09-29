import os
from functools import lru_cache
from typing import List

from localstack import config
from localstack.packages import GitHubReleaseInstaller, InstallTarget, Package, PackageInstaller
from localstack.utils.files import replace_in_file
from localstack.utils.platform import get_arch, get_os
from localstack.utils.run import run

_KINESIS_MOCK_VERSION = os.environ.get("KINESIS_MOCK_VERSION") or "0.2.5"


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

    def _get_github_asset_name(self, _):
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


# kinesalite version (npm dependency)
_KINESALITE_VERSION = os.environ.get("KINESALITE_VERSION") or "3.3.3"


class KinesalitePackage(Package):
    def __init__(self, default_version: str = _KINESALITE_VERSION):
        super().__init__(name="Kinesalite", default_version=default_version)

    def _get_installer(self, version: str) -> PackageInstaller:
        return KinesalitePackageInstaller(version)

    def get_versions(self) -> List[str]:
        return [_KINESALITE_VERSION]


class KinesalitePackageInstaller(PackageInstaller):
    def __init__(self, version: str):
        super().__init__("kinesalite", version)

    def _get_install_marker_path(self, install_dir: str) -> str:
        return os.path.join(install_dir, "node_modules", "kinesalite", "cli.js")

    def _install(self, target: InstallTarget) -> None:
        run(
            [
                "npm",
                "install",
                "--prefix",
                self._get_install_dir(target),
                f"kinesalite@{self.version}",
            ]
        )

    def _post_process(self, target: InstallTarget) -> None:
        base_dir = self._get_install_dir(target)
        files = [
            "%s/kinesalite/validations/decreaseStreamRetentionPeriod.js",
            "%s/kinesalite/validations/increaseStreamRetentionPeriod.js",
        ]
        for file_path in files:
            file_path = file_path % base_dir
            replace_in_file("lessThanOrEqual: 168", "lessThanOrEqual: 8760", file_path)


kinesismock_package = KinesisMockPackage()
kinesalite_package = KinesalitePackage()
