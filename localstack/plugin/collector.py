import abc
import importlib
import inspect
import logging
import sys
from collections import defaultdict
from types import ModuleType
from typing import Dict, Iterable, List, NamedTuple

from .core import PluginSpec, PluginSpecResolver

LOG = logging.getLogger(__name__)


class EntryPoint(NamedTuple):
    name: str
    value: str
    group: str


EntryPointDict = Dict[str, List[str]]


def to_entry_point_dict(eps: List[EntryPoint]) -> EntryPointDict:
    result = defaultdict(list)
    for ep in eps:
        result[ep.group].append("%s=%s" % (ep.name, ep.value))
    return result


def spec_to_entry_point(spec: PluginSpec) -> EntryPoint:
    module = inspect.getmodule(spec.factory)
    name = spec.factory.__name__
    path = f"{module}:{name}"
    return EntryPoint(group=spec.namespace, name=spec.name, value=path)


class PluginCollector(abc.ABC):
    def get_entry_points(self) -> EntryPointDict:
        """
        Creates a dictionary for the entry_points attribute of setuptools' setup(), where keys are
        stevedore plugin namespaces, and values are lists of "name = module:object" pairs.

        :return: an entry_point dictionary
        """
        return to_entry_point_dict([spec_to_entry_point(spec) for spec in self.collect_plugins()])

    def collect_plugins(self) -> List[PluginSpec]:
        raise NotImplementedError


class ModuleScanningPluginCollector(PluginCollector):
    """
    A PluginCollector that scans the members of given modules for available PluginSpecs. Each member is evaluated
    with a PluginSpecResolver, and all successful calls resulting in a PluginSpec are collected and returned.
    """

    def __init__(self, modules: Iterable[ModuleType], resolver: PluginSpecResolver = None) -> None:
        super().__init__()
        self.modules = modules
        self.resolver = resolver or PluginSpecResolver()

    def collect_plugins(self) -> List[PluginSpec]:
        plugins = list()

        for module in self.modules:
            LOG.debug("scanning module %s", module.__name__)
            members = inspect.getmembers(module)

            for member in members:
                if type(member) is tuple:
                    try:
                        spec = self.resolver.resolve(member[1])
                        plugins.append(spec)
                        LOG.info("found plugin spec in %s:%s %s", module.__name__, member[0], spec)
                    except Exception:
                        pass

        return plugins


class SetuptoolsPluginCollector(PluginCollector):
    """
    Uses setuptools and pkgutil to find and import modules (with the same API as setuptools.find_packages),
    and then uses a ModuleScanningPluginCollector to resolve the available plugins.
    """

    def __init__(self, where=".", exclude=(), include=("*",)) -> None:
        self.where = where
        self.exclude = exclude
        self.include = include

    def collect_plugins(self) -> List[PluginSpec]:
        collector = ModuleScanningPluginCollector(self.load_modules())
        return collector.collect_plugins()

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
            pkgpath = self.where + "/" + pkg.replace(".", "/")
            if sys.version_info.major == 2 or (
                sys.version_info.major == 3 and sys.version_info.minor < 6
            ):
                for _, name, is_pkg in iter_modules([pkgpath]):
                    if not is_pkg:
                        modules.add(pkg + "." + name)
            else:
                for info in iter_modules([pkgpath]):
                    if not info.ispkg:
                        modules.add(pkg + "." + info.name)

        return modules
