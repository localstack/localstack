import importlib
import inspect
import logging
import os
from types import ModuleType
from typing import Iterable, List

from .core import PluginFinder, PluginSpec, PluginSpecResolver

LOG = logging.getLogger(__name__)


class ModuleScanningPluginFinder(PluginFinder):
    """
    A PluginFinder that scans the members of given modules for available PluginSpecs. Each member is evaluated
    with a PluginSpecResolver, and all successful calls resulting in a PluginSpec are collected and returned.
    """

    def __init__(self, modules: Iterable[ModuleType], resolver: PluginSpecResolver = None) -> None:
        super().__init__()
        self.modules = modules
        self.resolver = resolver or PluginSpecResolver()

    def find_plugins(self) -> List[PluginSpec]:
        plugins = list()

        for module in self.modules:
            LOG.debug("scanning module %s", module.__name__)
            members = inspect.getmembers(module)

            for member in members:
                if type(member) is tuple:
                    try:
                        spec = self.resolver.resolve(member[1])
                        plugins.append(spec)
                        LOG.debug("found plugin spec in %s:%s %s", module.__name__, member[0], spec)
                    except Exception:
                        pass

        return plugins


class PackagePathPluginFinder(PluginFinder):
    """
    Uses setuptools and pkgutil to find and import modules within a given path and then uses a
    ModuleScanningPluginFinder to resolve the available plugins. The constructor has the same signature as
    setuptools.find_packages(where, exclude, include).
    """

    def __init__(self, where=".", exclude=(), include=("*",)) -> None:
        self.where = where
        self.exclude = exclude
        self.include = include

    def find_plugins(self) -> List[PluginSpec]:
        collector = ModuleScanningPluginFinder(self.load_modules())
        return collector.find_plugins()

    def load_modules(self):
        for module_name in self.list_module_names():
            try:
                yield importlib.import_module(module_name)
            except Exception as e:
                LOG.error("error importing module %s: %s", module_name, e)

    def list_module_names(self):
        # adapted from https://stackoverflow.com/a/54323162/804840
        from pkgutil import iter_modules

        from setuptools import find_packages

        modules = set()

        for pkg in find_packages(self.where, self.exclude, self.include):
            modules.add(pkg)
            pkgpath = self.where + os.sep + pkg.replace(".", os.sep)
            for info in iter_modules([pkgpath]):
                if not info.ispkg:
                    modules.add(pkg + "." + info.name)

        return modules
