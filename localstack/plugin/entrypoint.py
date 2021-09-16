import inspect
from collections import defaultdict
from typing import Dict, List, NamedTuple

from .core import PluginFinder, PluginSpec
from .discovery import PackagePathPluginFinder


class EntryPoint(NamedTuple):
    name: str
    value: str
    group: str


EntryPointDict = Dict[str, List[str]]


def discover_entry_points(finder: PluginFinder) -> EntryPointDict:
    """
    Creates a dictionary for the entry_points attribute of setuptools' setup(), where keys are
    stevedore plugin namespaces, and values are lists of "name = module:object" pairs.

    :return: an entry_point dictionary
    """
    return to_entry_point_dict([spec_to_entry_point(spec) for spec in finder.find_plugins()])


def to_entry_point_dict(eps: List[EntryPoint]) -> EntryPointDict:
    result = defaultdict(list)
    names = defaultdict(set)  # book-keeping to check duplicates

    for ep in eps:
        if ep.name in names[ep.group]:
            raise ValueError("Duplicate entry point %s %s" % (ep.group, ep.name))

        result[ep.group].append("%s=%s" % (ep.name, ep.value))
        names[ep.group].add(ep.name)

    return result


def spec_to_entry_point(spec: PluginSpec) -> EntryPoint:
    module = inspect.getmodule(spec.factory).__name__
    name = spec.factory.__name__
    path = f"{module}:{name}"
    return EntryPoint(group=spec.namespace, name=spec.name, value=path)


def find_plugins(where=".", exclude=(), include=("*",)) -> EntryPointDict:
    """
    Utility for setup.py that collects all plugins from the specified path, and creates a dictionary for entry_points.

    For example:

    setup(
        entry_points=find_plugins()
    )
    """

    return discover_entry_points(
        PackagePathPluginFinder(where=where, exclude=exclude, include=include)
    )
