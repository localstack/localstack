import abc
import functools
import logging
import os
import threading
from abc import ABC
from enum import Enum
from inspect import getmodule
from typing import Callable, List, Optional

from plugin import Plugin, PluginManager, PluginSpec

from localstack import config
from localstack.utils.platform import in_docker, is_debian, is_redhat
from localstack.utils.run import run

LOG = logging.getLogger(__name__)

PLUGIN_NAMESPACE = "localstack.packages"


class PackageException(Exception):
    pass


class NoSuchInstallTargetException(PackageException):
    pass


class NoSuchVersionException(PackageException):
    pass


class SystemNotSupportedException(NotImplementedError, PackageException):
    pass


class InstallTarget(Enum):
    VAR_LIBS = config.dirs.var_libs
    STATIC_LIBS = config.dirs.static_libs


class PackageInstaller(abc.ABC):
    def __init__(self, name: str):
        self.name = name

    def install(self, target: Optional[InstallTarget] = None):
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

    def is_installed(self) -> bool:
        return self.get_installed_dir() is not None

    def get_installed_dir(self) -> str:
        for target in InstallTarget:
            directory = self._get_install_dir(target)
            if directory and os.path.exists(directory):
                return directory

    def get_executables_path(self) -> str | None:
        directory = self.get_installed_dir()
        if directory:
            return self._build_executables_path(directory)

    def _get_install_dir(self, target: InstallTarget):
        return os.path.join(target.value, self.name, self.version)

    def _build_executables_path(self, install_dir: str):
        raise NotImplementedError()

    def _prepare_installation(self, target: InstallTarget):
        pass

    def _install(self, target: InstallTarget):
        raise NotImplementedError()

    def _post_process(self, target: InstallTarget):
        pass


OS_PACKAGE_INSTALL_LOCK = threading.RLock()
_DEBIAN_CACHE_DIR = os.path.join(config.dirs.cache, "apt")


class OSPackageInstaller(PackageInstaller, ABC):
    def __init__(self, name: str):
        super().__init__(name)

    def _get_install_dir(self, target: InstallTarget):
        with OS_PACKAGE_INSTALL_LOCK:
            self._os_switch(
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

    def _prepare_installation(self, target: InstallTarget):
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

    def _install(self, target: InstallTarget):
        with OS_PACKAGE_INSTALL_LOCK:
            self._os_switch(debian=self._debian_install, redhat=self._redhat_install, target=target)

    def _post_process(self, target: InstallTarget):
        with OS_PACKAGE_INSTALL_LOCK:
            self._os_switch(
                debian=self._debian_post_process, redhat=self._redhat_post_process, target=target
            )

    def _debian_get_install_dir(self, target: InstallTarget):
        raise SystemNotSupportedException(
            f"There is no supported installation method for {self.name} on Debian."
        )

    def _debian_packages(self) -> List[str]:
        raise SystemNotSupportedException(
            f"There is no supported installation method for {self.name} on Debian."
        )

    def _debian_prepare_install(self, target: InstallTarget):
        run(self._debian_cmd_prefix() + ["update"])

    def _debian_install(self, target: InstallTarget):
        debian_packages = self._debian_packages()
        LOG.debug("Downloading packages %s to folder: %s", packages, _DEBIAN_CACHE_DIR)
        cmd = self._debian_cmd_prefix() + ["-d", "install"] + debian_packages
        run(cmd)
        cmd = self._debian_cmd_prefix() + ["install"] + debian_packages
        run(cmd)

    def _debian_post_process(self, target: InstallTarget):
        # TODO maybe remove the debian cache dir here?
        ...

    def _debian_cmd_prefix(self) -> List[str]:
        """Return the apt command prefix, configuring the local package cache folders"""
        return [
            "apt",
            f"-o=dir::cache={_DEBIAN_CACHE_DIR}",
            f"-o=dir::cache::archives={_DEBIAN_CACHE_DIR}",
            "-y",
        ]

    def _redhat_get_install_dir(self, target: InstallTarget):
        raise SystemNotSupportedException(
            f"There is no supported installation method for {self.name} on RedHat."
        )

    def _redhat_packages(self) -> List[str]:
        raise SystemNotSupportedException(
            f"There is no supported installation method for {self.name} on RedHat."
        )

    def _redhat_prepare_install(self, target: InstallTarget):
        ...

    def _redhat_install(self, target: InstallTarget):
        run(["dnf", "install", "-y"] + self._redhat_packages())

    def _redhat_post_process(self, target: InstallTarget):
        run(["dnf", "clean", "all"])


class Package(abc.ABC):
    def __init__(self, name: str, default_version: str):
        self.name = name
        self.default_version = default_version

    def get_executables_path(self, version: str | None = None) -> str | None:
        return self.get_installer(version).get_executables_path()

    def get_installed_dir(self, version: str | None = None) -> str | None:
        return self.get_installer(version).get_installed_dir()

    def install(self, version: str | None = None, target: Optional[InstallTarget] = None):
        self.get_installer(version).install(target)

    def get_installer(self, version: str | None = None) -> PackageInstaller:
        if not version:
            version = self.default_version
        if version not in self.get_versions():
            raise NoSuchVersionException()
        return self._get_installer(version)

    def get_versions(self) -> List[str]:
        raise NotImplementedError()

    def _get_installer(self, version: str):
        raise NotImplementedError()

    def __str__(self):
        return self.name


class PackageRepository(PluginManager):
    def __init__(self):
        super().__init__(namespace=PLUGIN_NAMESPACE)


class PackagesPlugin(Plugin):
    service: str

    def __init__(
        self,
        service: str,
        get_packages: Callable[[], Package | List[Package]],
    ) -> None:
        super().__init__()
        self.service = service
        self._get_packages = get_packages

    def get_packages(self) -> List[Package]:
        packages = self._get_packages()
        return packages if isinstance(packages, list) else [packages]


def packages(service: Optional[str] = None, name: Optional[str] = "default"):
    def wrapper(fn):
        @functools.wraps(fn)
        def factory() -> PackagesPlugin:
            _service = service or getmodule(fn).__name__
            return PackagesPlugin(service=_service, get_packages=fn)

        return PluginSpec(PLUGIN_NAMESPACE, f"{service}:{name}", factory=factory)

    return wrapper
