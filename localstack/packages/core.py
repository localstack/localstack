import logging
import os
import threading
from abc import ABC
from functools import lru_cache
from typing import Callable, Dict, List

import requests

from localstack import config
from localstack.utils.platform import in_docker, is_debian, is_redhat
from localstack.utils.run import run

from ..utils.files import chmod_r, mkdir
from ..utils.http import download
from .api import InstallTarget, PackageException, PackageInstaller

LOG = logging.getLogger(__name__)


# Lock which is used for OS package installations (to avoid locking issues)
OS_PACKAGE_INSTALL_LOCK = threading.RLock()

# Cache directory for APT / the debian package manager.
_DEBIAN_CACHE_DIR = os.path.join(config.dirs.cache, "apt")


class SystemNotSupportedException(PackageException):
    """Exception indicating that the current system is not allowed."""

    pass


class OSPackageInstaller(PackageInstaller, ABC):
    """
    TODO make sure to log the output of all "run" commands (at least on trace level)
    Package installer abstraction for packages which are installed on operating system level, using the OS package
    manager.
    These packages are exceptional, since they cannot be installed to a specific target.
    If an OS level package is about to be installed to VAR_LIBS (i.e. it is installed at runtime and should persist
    across container-recreations), a warning will be logged and - depending on the OS - there might be some caching
    optimizations.
    """

    def __init__(self, name: str, version: str):
        super().__init__(name, version)

    def _get_install_dir(self, target: InstallTarget) -> str:
        return self._os_switch(
            debian=self._debian_get_install_dir,
            redhat=self._redhat_get_install_dir,
            target=target,
        )

    @staticmethod
    def _os_switch(debian: Callable, redhat: Callable, **kwargs):
        if not in_docker():
            raise SystemNotSupportedException(
                "OS level packages are only installed within docker containers."
            )
        if is_debian():
            return debian(**kwargs)
        elif is_redhat():
            return redhat(**kwargs)
        else:
            raise SystemNotSupportedException(
                "The current operating system is currently not supported."
            )

    def _prepare_installation(self, target: InstallTarget) -> None:
        if target != InstallTarget.STATIC_LIBS:
            LOG.warning(
                "%s will be installed as an OS package, even though install target is _not_ set to be static.",
                self.name,
            )
        with OS_PACKAGE_INSTALL_LOCK:
            self._os_switch(
                debian=self._debian_prepare_install,
                redhat=self._redhat_prepare_install,
                target=target,
            )

    def _install(self, target: InstallTarget) -> None:
        with OS_PACKAGE_INSTALL_LOCK:
            self._os_switch(debian=self._debian_install, redhat=self._redhat_install, target=target)

    def _post_process(self, target: InstallTarget) -> None:
        with OS_PACKAGE_INSTALL_LOCK:
            self._os_switch(
                debian=self._debian_post_process, redhat=self._redhat_post_process, target=target
            )

    def _get_install_marker_path(self, install_dir: str) -> str:
        return self._os_switch(
            debian=self._debian_get_install_marker_path,
            redhat=self._redhat_get_install_marker_path,
            install_dir=install_dir,
        )

    def _debian_get_install_dir(self, target: InstallTarget) -> str:
        raise SystemNotSupportedException(
            f"There is no supported installation method for {self.name} on Debian."
        )

    def _debian_get_install_marker_path(self, install_dir: str) -> str:
        raise SystemNotSupportedException(
            f"There is no supported installation method for {self.name} on Debian."
        )

    def _debian_packages(self) -> List[str]:
        raise SystemNotSupportedException(
            f"There is no supported installation method for {self.name} on Debian."
        )

    def _debian_prepare_install(self, target: InstallTarget) -> None:
        run(self._debian_cmd_prefix() + ["update"])

    def _debian_install(self, target: InstallTarget) -> None:
        debian_packages = self._debian_packages()
        LOG.debug("Downloading packages %s to folder: %s", debian_packages, _DEBIAN_CACHE_DIR)
        cmd = self._debian_cmd_prefix() + ["-d", "install"] + debian_packages
        run(cmd)
        cmd = self._debian_cmd_prefix() + ["install"] + debian_packages
        run(cmd)

    def _debian_post_process(self, target: InstallTarget) -> None:
        # TODO maybe remove the debian cache dir here?
        pass

    def _debian_cmd_prefix(self) -> List[str]:
        """Return the apt command prefix, configuring the local package cache folders"""
        return [
            "apt",
            f"-o=dir::cache={_DEBIAN_CACHE_DIR}",
            f"-o=dir::cache::archives={_DEBIAN_CACHE_DIR}",
            "-y",
        ]

    def _redhat_get_install_dir(self, target: InstallTarget) -> str:
        raise SystemNotSupportedException(
            f"There is no supported installation method for {self.name} on RedHat."
        )

    def _redhat_get_install_marker_path(self, install_dir: str) -> str:
        raise SystemNotSupportedException(
            f"There is no supported installation method for {self.name} on Debian."
        )

    def _redhat_packages(self) -> List[str]:
        raise SystemNotSupportedException(
            f"There is no supported installation method for {self.name} on RedHat."
        )

    def _redhat_prepare_install(self, target: InstallTarget) -> None:
        pass

    def _redhat_install(self, target: InstallTarget) -> None:
        run(["dnf", "install", "-y"] + self._redhat_packages())

    def _redhat_post_process(self, target: InstallTarget) -> None:
        run(["dnf", "clean", "all"])


class DownloadInstaller(PackageInstaller):
    def __init__(self, name: str, version: str):
        super().__init__(name, version)

    def _get_download_url(self) -> str:
        raise NotImplementedError()

    def _get_install_marker_path(self, install_dir: str) -> str:
        url = self._get_download_url()
        binary_name = os.path.basename(url)
        return os.path.join(install_dir, binary_name)

    def get_executable_path(self) -> str | None:
        """
        :return: the path to the downloaded binary or None if it's not yet downloaded / installed.
        """
        install_dir = self.get_installed_dir()
        if install_dir:
            return self._get_install_marker_path(install_dir)

    def _install(self, target: InstallTarget) -> None:
        target_directory = self._get_install_dir(target)
        mkdir(target_directory)
        download_url = self._get_download_url()
        target_path = self._get_install_marker_path(target_directory)
        download(download_url, target_path)
        chmod_r(target_path, 0o777)


class GitHubReleaseInstaller(DownloadInstaller):
    """
    Installer which downloads an asset from a GitHub project's tag.
    """

    def __init__(self, name: str, tag: str, github_slug: str):
        super().__init__(name, tag)
        self.github_tag_url = (
            f"https://api.github.com/repos/{github_slug}/releases/tags/{self.version}"
        )

    @lru_cache()
    def _get_download_url(self) -> str:
        response = requests.get(self.github_tag_url)
        if not response.ok:
            raise PackageException(
                f"Could not get list of releases from {self.github_tag_url}: {response.text}"
            )
        github_release = response.json()
        asset_name = self._get_github_asset_name(github_release)
        download_url = None
        for asset in github_release.get("assets", []):
            # find the correct binary in the release
            if asset["name"] == asset_name:
                download_url = asset["browser_download_url"]
                break
        if download_url is None:
            raise PackageException(
                f"Could not find required binary {asset_name} in release {self.github_tag_url}"
            )
        return download_url

    def _get_github_asset_name(self, github_release: Dict) -> str:
        """
        Determines the name of the asset to download.

        :param github_release: GitHub Release JSON data
        :return: name of the asset to download from the GitHub project's tag / version
        """
        raise NotImplementedError()
