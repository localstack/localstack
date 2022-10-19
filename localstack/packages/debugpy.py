import os
from typing import List

from localstack.packages import InstallTarget, Package, PackageInstaller

# debugpy module
DEBUGPY_MODULE = "debugpy"


class DebugPyPackage(Package):
    def __init__(self):
        super().__init__("DebugPy", "latest")

    def get_versions(self) -> List[str]:
        return ["latest"]

    def _get_installer(self, version: str) -> PackageInstaller:
        return DebugPyPackageInstaller("debugpy", version)


class DebugPyPackageInstaller(PackageInstaller):
    def _get_install_dir(self, target: InstallTarget) -> str:
        import inspect
        from pathlib import Path

        import localstack

        # get the "root" LocalStack directory. We go two levels up from /localstack/localstack/__init__.py
        ls_path = Path(inspect.getfile(localstack)).parent.parent
        # TODO: make this python version independent
        lib_path = os.path.join(ls_path, ".venv/lib/python3.10/site-packages/debugpy")
        return lib_path

    def _get_install_marker_path(self, install_dir: str) -> str:
        return install_dir

    def _install(self, target: InstallTarget) -> None:
        import pip

        if hasattr(pip, "main"):
            pip.main(["install", DEBUGPY_MODULE])
        else:
            pip._internal.main(["install", DEBUGPY_MODULE])


debugpy_package = DebugPyPackage()
