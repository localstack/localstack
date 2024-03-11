import logging
from typing import List

from localstack.constants import ARTIFACTS_REPO
from localstack.packages import InstallTarget, Package, PackageInstaller
from localstack.packages.core import PermissionDownloadInstaller
from localstack.utils.files import chmod_r, mkdir
from localstack.utils.http import download_github_artifact
from localstack.utils.run import run

LOG = logging.getLogger(__name__)


class FunctionTracePackage(Package):
    def __init__(self):
        super().__init__("FunctionTrace", "latest")

    def get_versions(self) -> List[str]:
        return ["latest"]

    def _get_installer(self, version: str) -> PackageInstaller:
        return FunctionTracePackageInstaller("functiontrace", version)


class FunctionTracePackageInstaller(PackageInstaller):
    # TODO: migrate this to the upcoming pip installer

    def is_installed(self) -> bool:
        try:
            import functiontrace

            assert functiontrace
            return True
        except ModuleNotFoundError:
            return False

    def _get_install_marker_path(self, install_dir: str) -> str:
        # TODO: This method currently does not provide the actual install_marker.
        #  Since we overwrote is_installed(), this installer does not install anything under
        #  var/static libs, and we also don't need an executable, we don't need it to operate the installer.
        #  fix with migration to pip installer
        return install_dir

    def _install(self, target: InstallTarget) -> None:
        cmd = "pip install functiontrace"
        run(cmd)


class FunctionTraceServerPackage(Package):
    def __init__(self):
        super().__init__("FunctionTraceServer", "latest")

    def get_versions(self) -> List[str]:
        return ["latest"]

    def _get_installer(self, version: str) -> PackageInstaller:
        return FunctionTraceServerPackageInstaller("functiontrace-server", version)


class FunctionTraceServerPackageInstaller(PermissionDownloadInstaller):
    # TODO: migrate this to the upcoming pip installer

    def _get_download_url(self) -> str:
        return (
            ARTIFACTS_REPO
            + "/raw/79c588fe97515a5124f58c4ae28201938084cc64/functiontrace/amd64/functiontrace-server"
        )

    def _install(self, target: InstallTarget) -> None:
        target_directory = self._get_install_dir(target)
        mkdir(target_directory)
        download_url = self._get_download_url()
        target_path = self._get_install_marker_path(target_directory)
        download_github_artifact(download_url, target_path)
        chmod_r(self.get_executable_path(), 0o777)


functiontrace_package = FunctionTracePackage()
functiontrace_server_package = FunctionTraceServerPackage()
