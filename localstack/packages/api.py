import abc
import functools
import logging
import os
from enum import Enum
from inspect import getmodule
from typing import Callable, Dict, List, Optional

from plugin import Plugin, PluginManager, PluginSpec

from localstack import config

LOG = logging.getLogger(__name__)

PLUGIN_NAMESPACE = "localstack.packages"


class PackageException(Exception):
    """Basic exception indicating that a package-specific exception occurred."""

    pass


class NoSuchVersionException(PackageException):
    """Exception indicating that a requested installer version is not available / supported."""

    pass


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

    def __init__(self, name: str, version: str):
        """
        :param name: technical package name, f.e. "opensearch"
        :param version: version of the package to install
        """
        self.name = name
        self.version = version

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
        :param version: version of the package to install. If None, the default version of the package will be used.
        :return: PackageInstaller instance for the given version.
        :raises NoSuchVersionException: If the given version is not supported.
        """
        if not version:
            version = self.default_version
        if version not in self.get_versions():
            raise NoSuchVersionException()
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


class PackageRepository(PluginManager):
    """
    PackageRepository is a plugin manager for PackagesPlugin instances.
    It discovers all plugins in the namespace "localstack.packages" and provides convenience functions to
    list the packages for each service.
    """

    # TODO couple the packages plugins to service providers instead of services
    #  - maybe integrate these into the ServicePluginManager

    def __init__(self):
        super().__init__(namespace=PLUGIN_NAMESPACE)

    def get_service_packages(self) -> Dict[str, List[Package]]:
        result = {}
        self.load_all()
        container_names = self.list_names()
        for container_name in container_names:
            container = self.get_container(container_name)
            service = container.plugin.service
            _packages: List[Package] = container.plugin.get_packages()
            result[service] = _packages
        return result


class PackagesPlugin(Plugin):
    """
    Plugin implementation for Package plugins.
    A package plugin bundles a specific service with a set of packages which are used by the service.
    """

    service: str

    def __init__(
        self,
        service: str,
        get_packages: Callable[[], Package | List[Package]],
        should_load: Callable[[], bool] = None,
    ) -> None:
        super().__init__()
        self.service = service
        self._get_packages = get_packages
        self._should_load = should_load

    def should_load(self) -> bool:
        if self._should_load:
            return self._should_load()
        return True

    def get_packages(self) -> List[Package]:
        """
        :return: list of package instances which are used by the service this PackagePlugin is associated with.
        """
        _packages = self._get_packages()
        return _packages if isinstance(_packages, list) else [_packages]


def packages(
    service: Optional[str] = None,
    name: Optional[str] = "default",
    should_load: Callable[[], bool] = None,
):
    """
    Decorator for marking methods that create Package instances as a PackagePlugin.
    Methods marked with this decorator are discoverable as a PluginSpec within the namespace "localstack.packages",
    with the name "<service>:<name>". If service is not explicitly specified, then the parent module name is used as
    service name.
    """

    def wrapper(fn):
        _service = service or getmodule(fn).__name__.split(".")[-2]

        @functools.wraps(fn)
        def factory() -> PackagesPlugin:
            return PackagesPlugin(service=_service, get_packages=fn, should_load=should_load)

        return PluginSpec(PLUGIN_NAMESPACE, f"{_service}:{name}", factory=factory)

    return wrapper
