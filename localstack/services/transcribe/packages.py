from typing import List

from localstack.packages import Package, PackageInstaller
from localstack.packages.core import PythonPackageInstaller

_VOSK_DEFAULT_VERSION = "0.3.43"


class VoskPackage(Package):
    def __init__(self, default_version: str = _VOSK_DEFAULT_VERSION):
        super().__init__(name="Vosk", default_version=default_version)

    def _get_installer(self, version: str) -> PackageInstaller:
        return VoskPackageInstaller(version)

    def get_versions(self) -> List[str]:
        return [_VOSK_DEFAULT_VERSION]


class VoskPackageInstaller(PythonPackageInstaller):
    def __init__(self, version: str):
        super().__init__("vosk", version)


vosk_package = VoskPackage()
