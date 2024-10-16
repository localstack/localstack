import logging
import os
from typing import List

import requests

from localstack.constants import USER_AGENT_STRING
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


class JavaInstallerMixin:
    """
    Mixin class for packages that depend on Java. It introduces methods that install Java and help build environment.
    """

    def _prepare_installation(self, target: InstallTarget) -> None:
        java_package.install(target=target)

    def get_java_home(self) -> str | None:
        """
        Returns path to JRE installation.
        """
        return java_package.get_installer().get_java_home()

    def get_java_env_vars(self, path: str = None, ld_library_path: str = None) -> dict[str, str]:
        """
        Returns environment variables pointing to the Java installation. This is useful to build the environment where
        the application will run.

        :param path: If not specified, the value of PATH will be obtained from the environment
        :param ld_library_path: If not specified, the value of LD_LIBRARY_PATH will be obtained from the environment
        :return: dict consisting of two items:
            - JAVA_HOME: path to JRE installation
            - PATH: the env path variable updated with JRE bin path
        """
        java_home = self.get_java_home()
        java_bin = f"{java_home}/bin"

        path = path or os.environ["PATH"]

        ld_library_path = ld_library_path or os.environ.get("LD_LIBRARY_PATH")
        # null paths (e.g. `:/foo`) have a special meaning according to the manpages
        if ld_library_path is None:
            ld_library_path = f"{java_home}/lib:{java_home}/lib/server"
        else:
            ld_library_path = f"{java_home}/lib:{java_home}/lib/server:{ld_library_path}"

        return {
            "JAVA_HOME": java_home,
            "LD_LIBRARY_PATH": ld_library_path,
            "PATH": f"{java_bin}:{path}",
        }


class JavaPackageInstaller(ArchiveDownloadAndExtractInstaller):
    def __init__(self, version: str):
        super().__init__("java", version, extract_single_directory=True)

    def _get_install_marker_path(self, install_dir: str) -> str:
        return os.path.join(install_dir, "bin", "java")

    def _get_download_url(self) -> str:
        try:
            LOG.debug("Determining the latest Java build version")
            return self._download_url_latest_release()
        except Exception as exc:  # noqa
            LOG.debug(
                "Unable to determine the latest Java build version. Using pinned versions: %s", exc
            )
            return self._download_url_fallback()

    def _post_process(self, target: InstallTarget) -> None:
        target_directory = self._get_install_dir(target)
        minimal_jre_path = os.path.join(target.value, self.name, f"{self.version}.minimal")
        rm_rf(minimal_jre_path)

        # If jlink is not available, use the environment as is
        if not os.path.exists(os.path.join(target_directory, "bin", "jlink")):
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
            # OpenSearch requires Thai locale for segmentation support
            "jdk.localedata --include-locales en,th "
            # Supplementary args
            "--compress 2 --strip-debug --no-header-files --no-man-pages "
            # Output directory
            "--output " + minimal_jre_path
        )
        run(cmd, cwd=target_directory)

        rm_rf(target_directory)
        os.rename(minimal_jre_path, target_directory)

    def get_java_home(self) -> str | None:
        """
        Get JAVA_HOME for this installation of Java.
        """
        return self.get_installed_dir()

    @property
    def arch(self) -> str:
        return (
            "x64" if get_arch() == Arch.amd64 else "aarch64" if get_arch() == Arch.arm64 else None
        )

    def _download_url_latest_release(self) -> str:
        """
        Return the download URL for latest stable JDK build.
        """
        endpoint = (
            f"https://api.adoptium.net/v3/assets/latest/{self.version}/hotspot?"
            f"os=linux&architecture={self.arch}&image_type=jdk"
        )
        # Override user-agent because Adoptium API denies service to `requests` library
        response = requests.get(endpoint, headers={"user-agent": USER_AGENT_STRING}).json()
        return response[0]["binary"]["package"]["link"]

    def _download_url_fallback(self) -> str:
        """
        Return the download URL for pinned JDK build.
        """
        os = "linux" if is_linux() else "mac" if is_mac_os() else None

        semver = JAVA_VERSIONS[self.version]
        tag_slug = f"jdk-{semver}"
        semver_safe = semver.replace("+", "_")

        # v8 uses a different tag and version scheme
        if self.version == "8":
            semver_safe = semver_safe.replace("-", "")
            tag_slug = f"jdk{semver}"

        return (
            f"https://github.com/adoptium/temurin{self.version}-binaries/releases/download/{tag_slug}/"
            f"OpenJDK{self.version}U-jdk_{self.arch}_{os}_hotspot_{semver_safe}.tar.gz"
        )


class JavaPackage(Package):
    def __init__(self, default_version: str = DEFAULT_JAVA_VERSION):
        super().__init__(name="Java", default_version=default_version)

    def get_versions(self) -> List[str]:
        return list(JAVA_VERSIONS.keys())

    def _get_installer(self, version):
        return JavaPackageInstaller(version)


java_package = JavaPackage()
