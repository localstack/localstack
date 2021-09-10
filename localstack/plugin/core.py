import abc
import inspect
from typing import Any, Callable, Dict, List, Tuple, Type, Union


class Plugin(abc.ABC):
    """A generic LocalStack plugin.

    A Plugin's primary function is to make it easy to be discovered, and to defer code imports into the Plugin::load
    method. Abstract subtypes of plugins (e.g., a LocalstackCliPlugin) may hook into

    Internally a Plugin is a wrapper around a setuptools EntryPoint. An entrypoint is a tuple: name, module:object
    inside a namespace that can be loaded. The entrypoint object of a LocalStack Plugin should always point to
    Plugin.__init__ (the constructor of the Plugin). Meaning that, loading the entry point is equivalent to
    instantiating the Plugin. A PluginLoader will then run the Plugin::load method.
    """

    namespace: str
    name: str
    requirements: List[str]

    def is_active(self) -> bool:
        # FIXME: remove after release (would currently break localstack-ext)
        return self.should_load()

    def should_load(self) -> bool:
        return True

    def load(self, *args, **kwargs):
        """
        Called by a PluginLoader when it loads the Plugin.
        """
        return None


PluginType = Type[Plugin]
PluginFactory = Callable[[], Plugin]


class PluginSpec:
    namespace: str
    name: str
    factory: PluginFactory
    metadata: Dict[str, Any]
    requirements: List[str]

    def __init__(
        self,
        namespace: str,
        name: str,
        factory: PluginFactory,
        metadata: Dict[str, Any] = None,
        requirements: List[str] = None,
    ) -> None:
        super().__init__()
        self.namespace = namespace
        self.name = name
        self.factory = factory
        self.requirements = requirements or []
        self.metadata = metadata or {}

    def __str__(self):
        return "PluginSpec(%s.%s = %s)" % (self.namespace, self.name, self.factory)

    def __repr__(self):
        return self.__str__()


class PluginSpecResolver:
    def resolve(self, source: Any) -> PluginSpec:
        """
        Tries to create a PluginSpec from the given source.
        :param source: anything that can produce a PluginSpec (Plugin class, ...)
        :return: a PluginSpec instance
        """
        if isinstance(source, PluginSpec):
            return source

        if inspect.isclass(source):
            if issubclass(source, Plugin):
                return PluginSpec(source.namespace, source.name, source)
            # TODO: check for @spec wrapper

        if inspect.isfunction(source):
            # TODO: check if is @spec wrapper
            pass

        # TODO: add more options to specify plugin specs

        raise ValueError("cannot resolve plugin specification from %s" % source)


class PluginLifecycleListener:
    def on_resolve_exception(self, namespace: str, entrypoint, exception: Exception):
        pass

    def on_resolve_after(self, plugin_spec: PluginSpec):
        pass

    def on_init_exception(self, plugin_spec: PluginSpec, exception: Exception):
        pass

    def on_init_after(self, plugin: Plugin):
        pass

    def on_load_before(self, plugin: Plugin, load_args: Union[List, Tuple], load_kwargs: Dict):
        pass

    def on_load_after(self, plugin: Plugin, load_result: Any = None):
        pass

    def on_load_exception(self, plugin: Plugin, exception: Exception):
        pass
