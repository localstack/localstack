import abc
import functools
import logging
import os
from collections import defaultdict
from enum import Enum
from inspect import getmodule
from threading import RLock
from typing import Callable, List, Optional, Tuple

from plugin import Plugin, PluginManager, PluginSpec

from localstack import config

LOG = logging.getLogger(__name__)


class PackageException(Exception):
    """Basic exception indicating that a package-specific exception occurred."""

    pass


class NoSuchVersionException(PackageException):
    """Exception indicating that a requested installer version is not available / supported."""

    def __init__(self, package: str = None, version: str = None):
        message = "Unable to find requested version"
        if package and version:
            message += f"Unable to find requested version '{version}' for package '{package}'"
        super().__init__(message)


class InstallTarget(Enum):
    """
    Different installation targets.
    Attention:
    - These targets are directly used in the LPM API and are therefore part of a public API!
    - The order of the entries in the enum define the default lookup order when looking for package installations.

    These targets refer to the directories in config#Directories.
    - VAR_LIBS: Used for packages installed at runtime. They are installed in a host-mounted volume.
                This directory / these installations persist across multiple containers.
    - STATIC_LIBS: Used for packages installed at build time. They are installed in a non-host-mounted volume.
                   This directory is re-created whenever a container is recreated.
    """

    VAR_LIBS = config.dirs.var_libs
    STATIC_LIBS = config.dirs.static_libs


class PackageInstaller(abc.ABC):
    """
    Base class for a specific installer.
    An instance of an installer manages the installation of a specific Package (in a specific version, if there are
    multiple versions).
    """

    def __init__(self, name: str, version: str, install_lock: Optional[RLock] = None):
        """
        :param name: technical package name, f.e. "opensearch"
        :param version: version of the package to install
        :param install_lock: custom lock which should be used for this package installer instance for the
                             complete #install call. Defaults to a per-instance reentrant lock (RLock).
                             Package instances create one installer per version. Therefore, by default, the lock
                             ensures that package installations of the same package and version are mutually exclusive.
        """
        self.name = name
        self.version = version
        self.install_lock = install_lock or RLock()

    def install(self, target: Optional[InstallTarget] = None) -> None:
        """
        Performs the package installation.

        :param target: preferred installation target. Default is VAR_LIBS.
        :return: None
        :raises PackageException: if the installation fails
        """
        try:
            if not target:
                target = InstallTarget.VAR_LIBS
            # We have to acquire the lock before checking if the package is installed, as the is_installed check
            # is _only_ reliable if no other thread is currently actually installing
            with self.install_lock:
                # Skip the installation if it's already installed
                if not self.is_installed():
                    LOG.debug("Starting installation of %s...", self.name)
                    self._prepare_installation(target)
                    self._install(target)
                    self._post_process(target)
                    LOG.debug("Installation of %s finished.", self.name)
                else:
                    LOG.debug("Installation of %s skipped (already installed).", self.name)
        except PackageException as e:
            raise e
        except Exception as e:
            raise PackageException(f"Installation of {self.name} failed.") from e

    def is_installed(self) -> bool:
        """
        Checks if the package is already installed.

        :return: True if the package is already installed (i.e. an installation is not necessary).
        """
        return self.get_installed_dir() is not None

    def get_installed_dir(self) -> str | None:
        """
        Returns the directory of an existing installation. The directory can differ based on the installation target
        and version.
        :return: str representation of the installation directory path or None if the package is not installed anywhere
        """
        for target in InstallTarget:
            directory = self._get_install_dir(target)
            if directory and os.path.exists(self._get_install_marker_path(directory)):
                return directory

    def _get_install_dir(self, target: InstallTarget) -> str:
        """
        Builds the installation directory for a specific target.
        :param target: to create the installation directory path for
        :return: str representation of the installation directory for the given target
        """
        return os.path.join(target.value, self.name, self.version)

    def _get_install_marker_path(self, install_dir: str) -> str:
        """
        Builds the path for a specific "marker" whose presence indicates that the package has been installed
        successfully in the given directory.

        :param install_dir: base path for the check (f.e. /var/lib/localstack/lib/dynamodblocal/latest/)
        :return: path which should be checked to indicate if the package has been installed successfully
                 (f.e. /var/lib/localstack/lib/dynamodblocal/latest/DynamoDBLocal.jar)
        """
        raise NotImplementedError()

    def _prepare_installation(self, target: InstallTarget) -> None:
        """
        Internal function to prepare an installation, f.e. by downloading some data or installing an OS package repo.
        Can be implemented by specific installers.
        :param target: of the installation
        :return: None
        """
        pass

    def _install(self, target: InstallTarget) -> None:
        """
        Internal function to perform the actual installation.
        Must be implemented by specific installers.
        :param target: of the installation
        :return: None
        """
        raise NotImplementedError()

    def _post_process(self, target: InstallTarget) -> None:
        """
        Internal function to perform some post-processing, f.e. patching an installation or creating symlinks.
        :param target: of the installation
        :return: None
        """
        pass


class Package(abc.ABC):
    """
    A Package defines a specific kind of software, mostly used as backends or supporting system for service
    implementations.
    """

    def __init__(self, name: str, default_version: str):
        """
        :param name: Human readable name of the package, f.e. "PostgreSQL"
        :param default_version: Default version of the package which is used for installations if no version is defined
        """
        self.name = name
        self.default_version = default_version

    def get_installed_dir(self, version: str | None = None) -> str | None:
        """
        Finds a directory where the package (in the specific version) is installed.
        :param version: of the package to look for. If None, the default version of the package is used.
        :return: str representation of the path to the existing installation directory or None if the package in this
                 version is not yet installed.
        """
        return self.get_installer(version).get_installed_dir()

    def install(self, version: str | None = None, target: Optional[InstallTarget] = None) -> None:
        """
        Installs the package in the given version in the preferred target location.
        :param version: version of the package to install. If None, the default version of the package will be used.
        :param target: preferred installation target. If None, the var_libs directory is used.
        :raises NoSuchVersionException: If the given version is not supported.
        """
        self.get_installer(version).install(target)

    @functools.lru_cache()
    def get_installer(self, version: str | None = None) -> PackageInstaller:
        """
        Returns the installer instance for a specific version of the package.

        It is important that this be LRU cached. Installers have a mutex lock to prevent races, and it is necessary
        that this method returns the same installer instance for a given version.

        :param version: version of the package to install. If None, the default version of the package will be used.
        :return: PackageInstaller instance for the given version.
        :raises NoSuchVersionException: If the given version is not supported.
        """
        if not version:
            return self.get_installer(self.default_version)
        if version not in self.get_versions():
            raise NoSuchVersionException(package=self.name, version=version)
        return self._get_installer(version)

    def get_versions(self) -> List[str]:
        """
        :return: List of all versions available for this package.
        """
        raise NotImplementedError()

    def _get_installer(self, version: str) -> PackageInstaller:
        """
        Internal lookup function which needs to be implemented by specific packages.
        It creates PackageInstaller instances for the specific version.

        :param version: to find the installer for
        :return: PackageInstaller instance responsible for installing the given version of the package.
        """
        raise NotImplementedError()

    def __str__(self):
        return self.name


class MultiPackageInstaller(PackageInstaller):
    """
    PackageInstaller implementation which composes of multiple package installers.
    """

    def __init__(self, name: str, version: str, package_installer: List[PackageInstaller]):
        """
        :param name: of the (multi-)package installer
        :param version: of this (multi-)package installer
        :param package_installer: List of installers this multi-package installer consists of
        """
        super().__init__(name=name, version=version)

        assert isinstance(package_installer, list)
        assert len(package_installer) > 0
        self.package_installer = package_installer

    def install(self, target: Optional[InstallTarget] = None) -> None:
        """
        Installs the different packages this installer is composed of.

        :param target: which defines where to install the packages.
        :return: None
        """
        for package_installer in self.package_installer:
            package_installer.install(target=target)

    def get_installed_dir(self) -> str | None:
        # By default, use the installed-dir of the first package
        return self.package_installer[0].get_installed_dir()

    def _install(self, target: InstallTarget) -> None:
        # This package installer actually only calls other installers, we pass here
        pass

    def _get_install_dir(self, target: InstallTarget) -> str:
        # By default, use the install-dir of the first package
        return self.package_installer[0]._get_install_dir(target)

    def _get_install_marker_path(self, install_dir: str) -> str:
        # By default, use the install-marker-path of the first package
        return self.package_installer[0]._get_install_marker_path(install_dir)


PLUGIN_NAMESPACE = "localstack.packages"


class PackagesPlugin(Plugin):
    """
    Plugin implementation for Package plugins.
    A package plugin exposes a specific package instance.
    """

    api: str
    name: str

    def __init__(
        self,
        name: str,
        scope: str,
        get_package: Callable[[], Package | List[Package]],
        should_load: Callable[[], bool] = None,
    ) -> None:
        super().__init__()
        self.name = name
        self.scope = scope
        self._get_package = get_package
        self._should_load = should_load

    def should_load(self) -> bool:
        if self._should_load:
            return self._should_load()
        return True

    def get_package(self) -> Package:
        """
        :return: returns the package instance of this package plugin
        """
        return self._get_package()


class NoSuchPackageException(PackageException):
    """Exception raised by the PackagesPluginManager to indicate that a package / version is not available."""

    pass


class PackagesPluginManager(PluginManager[PackagesPlugin]):
    """PluginManager which simplifies the loading / access of PackagesPlugins and their exposed package instances."""

    def __init__(self):
        super().__init__(PLUGIN_NAMESPACE)

    def get_all_packages(self) -> List[Tuple[str, str, Package]]:
        return sorted(
            [(plugin.name, plugin.scope, plugin.get_package()) for plugin in self.load_all()]
        )

    def get_packages(
        self, package_names: List[str], version: Optional[str] = None
    ) -> List[Package]:
        # Plugin names are unique, but there could be multiple packages with the same name in different scopes
        plugin_specs_per_name = defaultdict(list)
        # Plugin names have the format "<package-name>/<scope>", build a dict of specs per package name for the lookup
        for plugin_spec in self.list_plugin_specs():
            (package_name, _, _) = plugin_spec.name.rpartition("/")
            plugin_specs_per_name[package_name].append(plugin_spec)

        package_instances: List[Package] = []
        for package_name in package_names:
            plugin_specs = plugin_specs_per_name.get(package_name)
            if not plugin_specs:
                raise NoSuchPackageException(
                    f"unable to locate installer for package {package_name}"
                )
            for plugin_spec in plugin_specs:
                package_instance = self.load(plugin_spec.name).get_package()
                package_instances.append(package_instance)
                if version and version not in package_instance.get_versions():
                    raise NoSuchPackageException(
                        f"unable to locate installer for package {package_name} and version {version}"
                    )

        return package_instances


def package(
    name: str = None, scope: str = "community", should_load: Optional[Callable[[], bool]] = None
):
    """
    Decorator for marking methods that create Package instances as a PackagePlugin.
    Methods marked with this decorator are discoverable as a PluginSpec within the namespace "localstack.packages",
    with the name "<name>:<scope>". If api is not explicitly specified, then the parent module name is used as
    service name.
    """

    def wrapper(fn):
        _name = name or getmodule(fn).__name__.split(".")[-2]

        @functools.wraps(fn)
        def factory() -> PackagesPlugin:
            return PackagesPlugin(name=_name, scope=scope, get_package=fn, should_load=should_load)

        return PluginSpec(PLUGIN_NAMESPACE, f"{_name}/{scope}", factory=factory)

    return wrapper


# TODO remove (only used for migrating to new #package decorator)
packages = package
