import glob
import logging
import os
from typing import List

import distro

from localstack.packages import InstallTarget, Package
from localstack.pro.core.packages import OSPackageInstaller  # FIXME@viren
from localstack.utils.files import save_file
from localstack.utils.http import download
from localstack.utils.run import run

LOG = logging.getLogger(__name__)

# Version that is preinstalled during Docker build
PREINSTALLED_JAVA_VERSION = "21"

# Versions supported by this package
JAVA_VERSIONS = ["8", "11", "21"]

# Java home dirs inside main container
# Note: configure $JAVA_8_HOME / $JAVA_11_HOME for testing in host mode
JAVA_8_HOME = os.environ.get("JAVA_8_HOME") or "/usr/lib/jvm/java-8"
JAVA_11_HOME = os.environ.get("JAVA_11_HOME") or "/usr/lib/jvm/java-11"
JAVA_21_HOME = os.environ.get("JAVA_21_HOME") or "/usr/lib/jvm/java-21"

ADOPTIUM_DNS_SKIP = "jfrog-prod-.*.s3.amazonaws.com"


class JavaPackageInstaller(OSPackageInstaller):
    """
    Installer to install custom Java OS packages, required, e.g., for older versions of Spark.
    Note: Currently only supported for Debian (not for Redhat)
    """

    def __init__(self, version: str):
        super().__init__("java", version)

    def is_installed(self) -> bool:
        java_home = self.get_java_home()
        return java_home and os.path.exists(os.path.join(java_home, "bin", "java"))

    def _debian_get_install_dir(self, target: InstallTarget):
        return self._get_jvm_install_dir()

    def _debian_get_install_marker_path(self, install_dir: str) -> str:
        return os.path.join(install_dir, "bin", "java")

    def _debian_packages(self) -> List[str]:
        if self.version == PREINSTALLED_JAVA_VERSION:
            return []
        return [f"temurin-{self.version}-jdk"]

    def _debian_prepare_install(self, target: InstallTarget):
        sources_file = "/etc/apt/sources.list.d/adoptium.list"
        key_file = "/etc/apt/trusted.gpg.d/adoptium.asc"
        openjdk_repo = "https://packages.adoptium.net/artifactory"
        if self.version != PREINSTALLED_JAVA_VERSION and not os.path.exists(sources_file):
            # update package index
            download(f"{openjdk_repo}/api/gpg/key/public", key_file)
            save_file(
                sources_file,
                f"deb https://packages.adoptium.net/artifactory/deb {distro.codename()} main",
            )
        # the new adoptium repository uses s3, so we need to exclude the buckets from transparent endpoint injection
        try:
            from localstack.dns import server as dns_server

            dns_server.exclude_from_resolution(ADOPTIUM_DNS_SKIP)
        except ImportError:
            LOG.debug("Cannot import DNS server - skipping modification to allow apt download")
        super()._debian_prepare_install(target)

    def _post_process(self, target: InstallTarget) -> None:
        try:
            from localstack.dns import server as dns_server

            dns_server.revert_exclude_from_resolution(ADOPTIUM_DNS_SKIP)
        except ImportError:
            LOG.debug("Cannot import DNS server - skipping revert of skip")
        target_dir = self._get_jvm_install_dir()
        install_dir = glob.glob(f"/usr/lib/jvm/*-{self.version}-jdk-*")[0]
        if not os.path.exists(target_dir):
            run(["ln", "-s", install_dir, target_dir])

    def _get_jvm_install_dir(self) -> str:
        return self.get_java_home()

    def get_java_home(self) -> str:
        if self.version == "8":
            return JAVA_8_HOME
        if self.version == "11":
            return JAVA_11_HOME
        if self.version == "21":
            return JAVA_21_HOME
        return f"/usr/lib/jvm/java-{self.version}"


class JavaPackage(Package):
    def __init__(self, default_version: str = PREINSTALLED_JAVA_VERSION):
        super().__init__(name="Java", default_version=default_version)

    def get_versions(self) -> List[str]:
        return JAVA_VERSIONS

    def _get_installer(self, version):
        return JavaPackageInstaller(version)


java_package = JavaPackage()
