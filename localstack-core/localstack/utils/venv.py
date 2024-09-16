import io
import os
import sys
from functools import cached_property
from pathlib import Path
from typing import Union


class VirtualEnvironment:
    """
    Encapsulates methods to operate and navigate on a python virtual environment.
    """

    def __init__(self, venv_dir: Union[str, os.PathLike]):
        self._venv_dir = venv_dir

    def create(self):
        """
        Uses the virtualenv cli to create the virtual environment.
        :return:
        """
        self.venv_dir.mkdir(parents=True, exist_ok=True)
        from venv import main

        main([str(self.venv_dir)])

    @property
    def exists(self) -> bool:
        """
        Checks whether the virtual environment exists by checking whether the site-package directory of the venv exists.
        :return: the if the venv exists
        :raises NotADirectoryError: if the venv path exists but is not a directory
        """
        try:
            return True if self.site_dir else False
        except FileNotFoundError:
            return False

    @cached_property
    def venv_dir(self) -> Path:
        """
        Returns the path of the virtual environment directory
        :return: the path to the venv
        """
        return Path(self._venv_dir).absolute()

    @cached_property
    def site_dir(self) -> Path:
        """
        Resolves and returns the site-packages directory of the virtual environment. Once resolved successfully the
        result is cached.

        :return: the path to the site-packages dir.
        :raise FileNotFoundError: if the venv does not exist or the site-packages could not be found, or there are
         multiple lib/python* directories.
        :raise NotADirectoryError: if the venv is not a directory
        """
        venv = self.venv_dir

        if not venv.exists():
            raise FileNotFoundError(f"expected venv directory to exist at {venv}")

        if not venv.is_dir():
            raise NotADirectoryError(f"expected {venv} to be a directory")

        matches = list(venv.glob("lib/python*/site-packages"))

        if not matches:
            raise FileNotFoundError(f"could not find site-packages directory in {venv}")

        if len(matches) > 1:
            raise FileNotFoundError(f"multiple python versions found in {venv}: {matches}")

        return matches[0]

    def inject_to_sys_path(self):
        path = str(self.site_dir)
        if path and path not in sys.path:
            sys.path.append(path)

    def add_pth(self, name, path: Union[str, os.PathLike, "VirtualEnvironment"]) -> None:
        """
        Add a <name>.pth file into the virtual environment and append the given path to it. Does nothing if the path
        is already in the file.

        :param name: the name of the path file (without the .pth extensions)
        :param path: the path to be appended
        """
        pth_file = self.site_dir / f"{name}.pth"

        if isinstance(path, VirtualEnvironment):
            path = path.site_dir

        line = io.text_encoding(str(path)) + "\n"

        if pth_file.exists() and line in pth_file.read_text():
            return

        with open(pth_file, "a") as fd:
            fd.write(line)
