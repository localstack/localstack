from localstack.packages import Package
from localstack.packages.core import PythonPackageInstaller

_VOSK_DEFAULT_VERSION = "0.3.43"


class VoskPackage(Package[PythonPackageInstaller]):
    def __init__(self, default_version: str = _VOSK_DEFAULT_VERSION):
        super().__init__(name="Vosk", default_version=default_version)

    def _get_installer(self, version: str) -> PythonPackageInstaller:
        return VoskPackageInstaller(version)

    def get_versions(self) -> list[str]:
        return [_VOSK_DEFAULT_VERSION]


class VoskPackageInstaller(PythonPackageInstaller):
    def __init__(self, version: str):
        super().__init__("vosk", version)


vosk_package = VoskPackage()
