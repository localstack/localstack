import logging
import os
import re
from abc import ABC
from functools import lru_cache
from sys import version_info
from typing import Optional, Tuple

import requests

from localstack import config

from ..constants import LOCALSTACK_VENV_FOLDER, MAVEN_REPO_URL
from ..utils.archives import download_and_extract
from ..utils.files import chmod_r, chown_r, mkdir, rm_rf
from ..utils.http import download
from ..utils.run import is_root, run
from ..utils.venv import VirtualEnvironment
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
        archive_path = os.path.join(config.dirs.tmp, archive_name)
        download_and_extract(
            download_url,
            retries=3,
            tmp_archive=archive_path,
            target_dir=target_directory,
        )
        rm_rf(archive_path)
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


class NodePackageInstaller(ExecutableInstaller):
    """Package installer for Node / NPM packages."""

    def __init__(
        self,
        package_name: str,
        version: str,
        package_spec: Optional[str] = None,
        main_module: str = "main.js",
    ):
        """
        Initializes the Node / NPM package installer.
        :param package_name: npm package name
        :param version: version of the package which should be installed
        :param package_spec: optional package spec for the installation.
                If not set, the package name and version will be used for the installation.
        :param main_module: main module file of the package
        """
        super().__init__(package_name, version)
        self.package_name = package_name
        # If the package spec is not explicitly set (f.e. to a repo), we build it and pin the version
        self.package_spec = package_spec or f"{self.package_name}@{version}"
        self.main_module = main_module

    def _get_install_marker_path(self, install_dir: str) -> str:
        return os.path.join(install_dir, "node_modules", self.package_name, self.main_module)

    def _install(self, target: InstallTarget) -> None:
        target_dir = self._get_install_dir(target)

        run(
            [
                "npm",
                "install",
                "--prefix",
                target_dir,
                self.package_spec,
            ]
        )
        # npm 9+ does _not_ set the ownership of files anymore if run as root
        # - https://github.blog/changelog/2022-10-24-npm-v9-0-0-released/
        # - https://github.com/npm/cli/pull/5704
        # - https://github.com/localstack/localstack/issues/7620
        if is_root():
            # if the package was installed as root, set the ownership manually
            LOG.debug("Setting ownership root:root on %s", target_dir)
            chown_r(target_dir, "root")


LOCALSTACK_VENV = VirtualEnvironment(LOCALSTACK_VENV_FOLDER)


class PythonPackageInstaller(PackageInstaller):
    """
    Package installer which allows the runtime-installation of additional python packages used by certain services.
    f.e. vosk as offline speech recognition toolkit (which is ~7MB in size compressed and ~26MB uncompressed).
    """

    normalized_name: str
    """Normalized package name according to PEP440."""

    def __init__(self, name: str, version: str, *args, **kwargs):
        super().__init__(name, version, *args, **kwargs)
        self.normalized_name = self._normalize_package_name(name)

    def _normalize_package_name(self, name: str):
        """
        Normalized the Python package name according to PEP440.
        https://packaging.python.org/en/latest/specifications/name-normalization/#name-normalization
        """
        return re.sub(r"[-_.]+", "-", name).lower()

    def _get_install_dir(self, target: InstallTarget) -> str:
        # all python installers share a venv
        return os.path.join(target.value, "python-packages")

    def _get_install_marker_path(self, install_dir: str) -> str:
        python_subdir = f"python{version_info[0]}.{version_info[1]}"
        dist_info_dir = f"{self.normalized_name}-{self.version}.dist-info"
        # the METADATA file is mandatory, use it as install marker
        return os.path.join(
            install_dir, "lib", python_subdir, "site-packages", dist_info_dir, "METADATA"
        )

    def _get_venv(self, target: InstallTarget) -> VirtualEnvironment:
        venv_dir = self._get_install_dir(target)
        return VirtualEnvironment(venv_dir)

    def _prepare_installation(self, target: InstallTarget) -> None:
        # make sure the venv is properly set up before installing the package
        venv = self._get_venv(target)
        if not venv.exists:
            LOG.info("creating virtual environment at %s", venv.venv_dir)
            venv.create()
            LOG.info("adding localstack venv path %s", venv.venv_dir)
            venv.add_pth("localstack-venv", LOCALSTACK_VENV)
        LOG.debug("injecting venv into path %s", venv.venv_dir)
        venv.inject_to_sys_path()

    def _install(self, target: InstallTarget) -> None:
        venv = self._get_venv(target)
        python_bin = os.path.join(venv.venv_dir, "bin/python")

        # run pip via the python binary of the venv
        run([python_bin, "-m", "pip", "install", f"{self.name}=={self.version}"], print_error=False)

    def _setup_existing_installation(self, target: InstallTarget) -> None:
        """If the venv is already present, it just needs to be initialized once."""
        self._prepare_installation(target)


class MavenDownloadInstaller(DownloadInstaller):
    """The packageURL is easy copy/pastable from the Maven central repository and the first package URL
    defines the package name and version.
    Example package_url: pkg:maven/software.amazon.event.ruler/event-ruler@1.7.3
    => name: event-ruler
    => version: 1.7.3
    """

    # Example: software.amazon.event.ruler
    group_id: str
    # Example: event-ruler
    artifact_id: str

    # Custom installation directory
    install_dir_suffix: str | None

    def __init__(self, package_url: str, install_dir_suffix: str | None = None):
        self.group_id, self.artifact_id, version = parse_maven_package_url(package_url)
        super().__init__(self.artifact_id, version)
        self.install_dir_suffix = install_dir_suffix

    def _get_download_url(self) -> str:
        group_id_path = self.group_id.replace(".", "/")
        return f"{MAVEN_REPO_URL}/{group_id_path}/{self.artifact_id}/{self.version}/{self.artifact_id}-{self.version}.jar"

    def _get_install_dir(self, target: InstallTarget) -> str:
        """Allow to overwrite the default installation directory.
        This enables downloading transitive dependencies into the same directory.
        """
        if self.install_dir_suffix:
            return os.path.join(target.value, self.install_dir_suffix)
        else:
            return super()._get_install_dir(target)


class MavenPackageInstaller(MavenDownloadInstaller):
    """Package installer for downloading Maven JARs, including optional dependencies.
    The first Maven package is used as main LPM package and other dependencies are installed additionally.
    Follows the Maven naming conventions: https://maven.apache.org/guides/mini/guide-naming-conventions.html
    """

    # Installers for Maven dependencies
    dependencies: list[MavenDownloadInstaller]

    def __init__(self, *package_urls: str):
        super().__init__(package_urls[0])
        self.dependencies = []

        # Create installers for dependencies
        for package_url in package_urls[1:]:
            install_dir_suffix = os.path.join(self.name, self.version)
            self.dependencies.append(MavenDownloadInstaller(package_url, install_dir_suffix))

    def _install(self, target: InstallTarget) -> None:
        # Install all dependencies first
        for dependency in self.dependencies:
            dependency._install(target)
        # Install the main Maven package once all dependencies are installed.
        # This main package indicates whether all dependencies are installed.
        super()._install(target)


def parse_maven_package_url(package_url: str) -> Tuple[str, str, str]:
    """Example: parse_maven_package_url("pkg:maven/software.amazon.event.ruler/event-ruler@1.7.3")
    -> software.amazon.event.ruler, event-ruler, 1.7.3
    """
    parts = package_url.split("/")
    group_id = parts[1]
    sub_parts = parts[2].split("@")
    artifact_id = sub_parts[0]
    version = sub_parts[1]
    return group_id, artifact_id, version
