from localstack.packages import Package, package
from localstack.packages.core import PythonPackageInstaller


@package(name="vosk")
def vosk_package() -> Package[PythonPackageInstaller]:
    from localstack.services.transcribe.packages import vosk_package

    return vosk_package
