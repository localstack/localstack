import os
from pathlib import Path
from typing import List

import pytest

from localstack.packages import InstallTarget, Package, PackageInstaller
from localstack.utils.files import rm_rf


class TestPackage(Package):
    def __init__(self):
        super().__init__("Test Package", "test-version")

    def get_versions(self) -> List[str]:
        return ["test-version"]

    def _get_installer(self, version: str) -> PackageInstaller:
        return TestPackageInstaller(version=version)


class TestPackageInstaller(PackageInstaller):
    def __init__(self, version: str):
        super().__init__("test-installer", version)

    def _get_install_marker_path(self, install_dir: str) -> str:
        return os.path.join(install_dir, "test-installer-marker")

    def _install(self, target: InstallTarget) -> None:
        path = Path(os.path.join(self._get_install_dir(target), "test-installer-marker"))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.touch()


@pytest.fixture(scope="module")
def test_package():
    package = TestPackage()
    if package.get_installed_dir():
        rm_rf(package.get_installed_dir())

    yield package

    if package.get_installed_dir():
        rm_rf(package.get_installed_dir())


def test_package_get_installer_caches_installers(test_package):
    assert test_package.get_installer() is test_package.get_installer(test_package.default_version)


def test_package_get_installed_dir_returns_none(test_package):
    assert test_package.get_installed_dir() is None


def test_package_get_installed_dir_returns_install_dir(test_package):
    test_package.install()
    assert test_package.get_installed_dir() is not None
