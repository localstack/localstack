import logging
import os
from typing import List

from localstack.packages import Package
from localstack.packages.core import ArchiveDownloadAndExtractInstaller
from localstack.utils.platform import Arch, get_arch, is_linux, is_mac_os

LOG = logging.getLogger(__name__)

# Default version if not specified
DEFAULT_JAVA_VERSION = "11"

# Supported Java LTS versions mapped with Eclipse Temurin build semvers
JAVA_VERSIONS = {
    "8": "8u422-b05",
    "11": "11.0.24+8",
    "17": "17.0.12+7",
    "21": "21.0.4+7",
}

JRE_DISTRIB_URL = "https://github.com/adoptium/temurin{version}-binaries/releases/download/{tag_slug}/OpenJDK{version}U-jre_{arch}_{os}_hotspot_{semver_safe}.tar.gz"


class JavaPackageInstaller(ArchiveDownloadAndExtractInstaller):
    def __init__(self, version: str):
        super().__init__("java", version, extract_single_directory=True)

        self.semver = JAVA_VERSIONS[version]

    def _get_install_marker_path(self, install_dir: str) -> str:
        return os.path.join(install_dir, self._get_archive_subdir())

    def _get_download_url(self) -> str:
        os = "linux" if is_linux() else "mac" if is_mac_os() else None
        arch = (
            "x64" if get_arch() == Arch.amd64 else "aarch64" if get_arch() == Arch.arm64 else None
        )

        tag_slug = f"jdk-{self.semver}"
        semver_safe = self.semver.replace("+", "_")

        # v8 uses a different tag and version scheme
        if self.version == "8":
            semver_safe = semver_safe.replace("-", "")
            tag_slug = f"jdk{self.semver}"

        return JRE_DISTRIB_URL.format(
            version=self.version, tag_slug=tag_slug, os=os, arch=arch, semver_safe=semver_safe
        )

    def _get_archive_subdir(self) -> str | None:
        return f"jdk-{self.semver}-jre"

    def get_java_home(self) -> str:
        return self.get_installed_dir()


class JavaPackage(Package):
    def __init__(self, default_version: str = DEFAULT_JAVA_VERSION):
        super().__init__(name="Java", default_version=default_version)

    def get_versions(self) -> List[str]:
        return list(JAVA_VERSIONS.keys())

    def _get_installer(self, version):
        return JavaPackageInstaller(version)


java_package = JavaPackage()
