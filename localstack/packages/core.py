import logging
import os
from abc import ABC
from functools import lru_cache

import requests

from localstack import config

from ..utils.archives import download_and_extract
from ..utils.files import chmod_r, mkdir, rm_rf
from ..utils.http import download
from .api import InstallTarget, PackageException, PackageInstaller

LOG = logging.getLogger(__name__)


class SystemNotSupportedException(PackageException):
    """Exception indicating that the current system is not allowed."""

    pass


class ExecutableInstaller(PackageInstaller, ABC):
    """
    This installer simply adds a clean interface for accessing a downloaded executable directly
    """

    def get_executable_path(self) -> str | None:
        """
        :return: the path to the downloaded binary or None if it's not yet downloaded / installed.
        """
        install_dir = self.get_installed_dir()
        if install_dir:
            return self._get_install_marker_path(install_dir)


class DownloadInstaller(ExecutableInstaller):
    def __init__(self, name: str, version: str):
        super().__init__(name, version)

    def _get_download_url(self) -> str:
        raise NotImplementedError()

    def _get_install_marker_path(self, install_dir: str) -> str:
        url = self._get_download_url()
        binary_name = os.path.basename(url)
        return os.path.join(install_dir, binary_name)

    def _install(self, target: InstallTarget) -> None:
        target_directory = self._get_install_dir(target)
        mkdir(target_directory)
        download_url = self._get_download_url()
        target_path = self._get_install_marker_path(target_directory)
        download(download_url, target_path)


class ArchiveDownloadAndExtractInstaller(ExecutableInstaller):
    def __init__(self, name: str, version: str, extract_single_directory: bool = False):
        """
        :param name: technical package name, f.e. "opensearch"
        :param version: version of the package to install
        :param extract_single_directory: whether to extract files from single root folder in the archive
        """
        super().__init__(name, version)
        self.extract_single_directory = extract_single_directory

    def _get_install_marker_path(self, install_dir: str) -> str:
        raise NotImplementedError()

    def _get_download_url(self) -> str:
        raise NotImplementedError()

    def get_installed_dir(self) -> str | None:
        installed_dir = super().get_installed_dir()
        subdir = self._get_archive_subdir()

        # If the specific installer defines a subdirectory, we return the subdirectory.
        # f.e. /var/lib/localstack/lib/amazon-mq/5.16.5/apache-activemq-5.16.5/
        if installed_dir and subdir:
            return os.path.join(installed_dir, subdir)

        return installed_dir

    def _get_archive_subdir(self) -> str | None:
        """
        :return: name of the subdirectory contained in the archive or none if the package content is at the root level
                of the archive
        """
        return None

    def get_executable_path(self) -> str | None:
        subdir = self._get_archive_subdir()
        if subdir is None:
            return super().get_executable_path()
        else:
            install_dir = self.get_installed_dir()
            if install_dir:
                install_dir = install_dir[: -len(subdir)]
                return self._get_install_marker_path(install_dir)

    def _install(self, target: InstallTarget) -> None:
        target_directory = self._get_install_dir(target)
        mkdir(target_directory)
        download_url = self._get_download_url()
        archive_name = os.path.basename(download_url)
        download_and_extract(
            download_url,
            retries=3,
            tmp_archive=os.path.join(config.dirs.tmp, archive_name),
            target_dir=target_directory,
        )
        if self.extract_single_directory:
            dir_contents = os.listdir(target_directory)
            if len(dir_contents) != 1:
                return
            target_subdir = os.path.join(target_directory, dir_contents[0])
            if not os.path.isdir(target_subdir):
                return
            os.rename(target_subdir, f"{target_directory}.backup")
            rm_rf(target_directory)
            os.rename(f"{target_directory}.backup", target_directory)


class PermissionDownloadInstaller(DownloadInstaller, ABC):
    def _install(self, target: InstallTarget) -> None:
        super()._install(target)
        chmod_r(self.get_executable_path(), 0o777)


class GitHubReleaseInstaller(PermissionDownloadInstaller):
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
        asset_name = self._get_github_asset_name()
        # try to use a token when calling the GH API for increased API rate limits
        headers = None
        gh_token = os.environ.get("GITHUB_API_TOKEN")
        if gh_token:
            headers = {"authorization": f"Bearer {gh_token}"}
        response = requests.get(self.github_tag_url, headers=headers)
        if not response.ok:
            raise PackageException(
                f"Could not get list of releases from {self.github_tag_url}: {response.text}"
            )
        github_release = response.json()
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

    def _get_install_marker_path(self, install_dir: str) -> str:
        # Use the GitHub asset name instead of the download URL (since the download URL needs to be fetched online).
        return os.path.join(install_dir, self._get_github_asset_name())

    def _get_github_asset_name(self) -> str:
        """
        Determines the name of the asset to download.
        The asset name must be determinable without having any online data (because it is used in offline scenarios to
        determine if the package is already installed).

        :return: name of the asset to download from the GitHub project's tag / version
        """
        raise NotImplementedError()
