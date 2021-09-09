import abc
import inspect
import logging
from collections import defaultdict
from typing import Dict, List, NamedTuple

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
    A PluginCollector that tries to resolve tuples in
    """

    def __init__(self, modules, resolver: PluginSpecResolver = None) -> None:
        super().__init__()
        self.modules = modules
        self.resolver = resolver or PluginSpecResolver()

    def collect_plugins(self) -> List[PluginSpec]:
        plugins = list()

        for module in self.modules:
            members = inspect.getmembers(module)
            for member in members:
                if type(member) is tuple:
                    try:
                        spec = self.resolver.resolve(member[1])
                        plugins.append(spec)
                    except Exception:
                        pass

        return plugins
