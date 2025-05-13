import os
from enum import StrEnum
from functools import lru_cache
from typing import Any, List

from localstack.packages import InstallTarget, Package
from localstack.packages.core import GitHubReleaseInstaller, NodePackageInstaller
from localstack.packages.java import JavaInstallerMixin, java_package

_KINESIS_MOCK_VERSION = os.environ.get("KINESIS_MOCK_VERSION") or "0.4.12"


class KinesisMockEngine(StrEnum):
    NODE = "node"
    SCALA = "scala"

    @classmethod
    def _missing_(cls, value: str | Any) -> str:
        # default to 'node' if invalid enum
        if not isinstance(value, str):
            return cls(cls.NODE)
        return cls.__members__.get(value.upper(), cls.NODE)


class KinesisMockNodePackageInstaller(NodePackageInstaller):
    def __init__(self, version: str):
        super().__init__(package_name="kinesis-local", version=version)


class KinesisMockScalaPackageInstaller(JavaInstallerMixin, GitHubReleaseInstaller):
    def __init__(self, version: str = _KINESIS_MOCK_VERSION):
        super().__init__(
            name="kinesis-local", tag=f"v{version}", github_slug="etspaceman/kinesis-mock"
        )

        # Kinesis Mock requires JRE 21+
        self.java_version = "21"

    def _get_github_asset_name(self) -> str:
        return "kinesis-mock.jar"

    def _prepare_installation(self, target: InstallTarget) -> None:
        java_package.get_installer(self.java_version).install(target)

    def get_java_home(self) -> str | None:
        """Override to use the specific Java version"""
        return java_package.get_installer(self.java_version).get_java_home()


class KinesisMockScalaPackage(Package[KinesisMockScalaPackageInstaller]):
    def __init__(
        self,
        default_version: str = _KINESIS_MOCK_VERSION,
    ):
        super().__init__(name="Kinesis Mock", default_version=default_version)

    @lru_cache
    def _get_installer(self, version: str) -> KinesisMockScalaPackageInstaller:
        return KinesisMockScalaPackageInstaller(version)

    def get_versions(self) -> List[str]:
        return [_KINESIS_MOCK_VERSION]  # Only supported on v0.4.12+


class KinesisMockNodePackage(Package[KinesisMockNodePackageInstaller]):
    def __init__(
        self,
        default_version: str = _KINESIS_MOCK_VERSION,
    ):
        super().__init__(name="Kinesis Mock", default_version=default_version)

    @lru_cache
    def _get_installer(self, version: str) -> KinesisMockNodePackageInstaller:
        return KinesisMockNodePackageInstaller(version)

    def get_versions(self) -> List[str]:
        return [_KINESIS_MOCK_VERSION]


# leave as 'kinesismock_package' for backwards compatability
kinesismock_package = KinesisMockNodePackage()
kinesismock_scala_package = KinesisMockScalaPackage()
