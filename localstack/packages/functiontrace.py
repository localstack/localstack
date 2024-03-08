from typing import List

from localstack.packages import InstallTarget, Package, PackageInstaller
from localstack.utils.run import run


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


functiontrace_package = FunctionTracePackage()
