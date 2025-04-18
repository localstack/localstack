import os
from functools import lru_cache
from typing import List

from localstack.packages import Package
from localstack.packages.core import NodePackageInstaller

_KINESIS_MOCK_VERSION = os.environ.get("KINESIS_MOCK_VERSION") or "0.4.9"


class KinesisMockPackage(Package[NodePackageInstaller]):
    def __init__(self, default_version: str = _KINESIS_MOCK_VERSION):
        super().__init__(name="Kinesis Mock", default_version=default_version)

    @lru_cache
    def _get_installer(self, version: str) -> NodePackageInstaller:
        return KinesisMockPackageInstaller(version)

    def get_versions(self) -> List[str]:
        return [_KINESIS_MOCK_VERSION]


class KinesisMockPackageInstaller(NodePackageInstaller):
    def __init__(self, version: str):
        super().__init__(package_name="kinesis-local", version=version)


kinesismock_package = KinesisMockPackage()
