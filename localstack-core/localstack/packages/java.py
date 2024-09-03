import logging
import os
from typing import List

from localstack.packages import InstallTarget, Package
from localstack.packages.core import ArchiveDownloadAndExtractInstaller
from localstack.utils.files import rm_rf
from localstack.utils.platform import Arch, get_arch, is_linux, is_mac_os
from localstack.utils.run import run

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

JDK_DOWNLOAD_URL = "https://github.com/adoptium/temurin{version}-binaries/releases/download/{tag_slug}/OpenJDK{version}U-jdk_{arch}_{os}_hotspot_{semver_safe}.tar.gz"


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

        return JDK_DOWNLOAD_URL.format(
            version=self.version, tag_slug=tag_slug, os=os, arch=arch, semver_safe=semver_safe
        )

    def _get_archive_subdir(self) -> str | None:
        return ""

    def _post_process(self, target: InstallTarget) -> None:
        target_directory = self._get_install_dir(target)
        minimal_jre_path = os.path.join(target.value, self.name, "jre-{self.version}-minimal")

        # If jlink is not available, use the environment as is
        if not os.path.exists(os.path.join(target_directory, "bin/jlink")):
            LOG.warning("Skipping JRE optimisation because jlink is not available")
            return

        # Build a custom JRE with only the necessary bits to minimise disk footprint
        LOG.debug("Optimising JRE installation")
        cmd = (
            "bin/jlink --add-modules "
            # Required modules
            "java.base,java.desktop,java.instrument,java.management,"
            "java.naming,java.scripting,java.sql,java.xml,jdk.compiler,"
            # jdk.unsupported contains sun.misc.Unsafe which is required by some dependencies
            "jdk.unsupported,"
            # Additional cipher suites
            "jdk.crypto.cryptoki,"
            # Archive support
            "jdk.zipfs,"
            # Required by MQ broker
            "jdk.httpserver,jdk.management,jdk.management.agent,"
            # Required by Spark and Hadoop
            "java.security.jgss,jdk.security.auth,"
            # Locales
            "jdk.localedata --include-locales en "
            # Supplementary args
            "--compress 2 --strip-debug --no-header-files --no-man-pages "
            # Output directory
            "--output " + minimal_jre_path
        )
        run(cmd, cwd=target_directory)

        rm_rf(target_directory)
        os.rename(minimal_jre_path, target_directory)

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
