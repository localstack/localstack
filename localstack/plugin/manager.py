import logging
import threading
from typing import Any, Callable, Dict, Generic, Iterable, List, Tuple, TypeVar, Union

from .core import (
    Plugin,
    PluginDisabled,
    PluginException,
    PluginFinder,
    PluginLifecycleListener,
    PluginSpec,
    PluginSpecResolver,
)

LOG = logging.getLogger(__name__)

P = TypeVar("P", bound=Plugin)


def _call_safe(func: Callable, args: Tuple, exception_message: str):
    """
    Call the given function with the given arguments, and if it fails, log the given exception_message.
    If logging.DEBUG is set for the logger, then we also log the traceback.

    :param func: function to call
    :param args: arguments to pass
    :param exception_message: message to log on exception
    :return: whatever the func returns
    """
    try:
        return func(*args)
    except Exception as e:
        if LOG.isEnabledFor(logging.DEBUG):
            LOG.exception(exception_message)
        else:
            LOG.error("%s: %s", exception_message, e)


class PluginLifecycleNotifierMixin:
    """
    Mixin that provides functions to dispatch calls to a PluginLifecycleListener in a safe way.
    """

    listener: PluginLifecycleListener

    def _fire_on_resolve_after(self, plugin_spec):
        _call_safe(
            self.listener.on_resolve_after,
            (plugin_spec,),  #
            "error while calling on_resolve_after",
        )

    def _fire_on_resolve_exception(self, namespace, entrypoint, exception):
        _call_safe(
            self.listener.on_resolve_exception,
            (namespace, entrypoint, exception),
            "error while calling on_resolve_exception",
        )

    def _fire_on_init_after(self, plugin_spec, plugin):
        _call_safe(
            self.listener.on_init_after,
            (
                plugin_spec,
                plugin,
            ),  #
            "error while calling on_init_after",
        )

    def _fire_on_init_exception(self, plugin_spec, exception):
        _call_safe(
            self.listener.on_init_exception,
            (plugin_spec, exception),
            "error while calling on_init_exception",
        )

    def _fire_on_load_before(self, plugin_spec, plugin, load_args, load_kwargs):
        _call_safe(
            self.listener.on_load_before,
            (plugin_spec, plugin, load_args, load_kwargs),
            "error while calling on_load_before",
        )

    def _fire_on_load_after(self, plugin_spec, plugin, result):
        _call_safe(
            self.listener.on_load_after,
            (plugin_spec, plugin, result),
            "error while calling on_load_after",
        )

    def _fire_on_load_exception(self, plugin_spec, plugin, exception):
        _call_safe(
            self.listener.on_load_exception,
            (plugin_spec, plugin, exception),
            "error while calling on_load_exception",
        )


class PluginContainer(Generic[P]):
    """
    Object to pass around the plugin state inside a PluginManager.
    """

    name: str
    lock: threading.RLock

    plugin_spec: PluginSpec
    plugin: P = None
    load_value: Any = None

    is_init: bool = False
    is_loaded: bool = False

    init_error: Exception = None
    load_error: Exception = None


class PluginManager(PluginLifecycleNotifierMixin, Generic[P]):
    """
    Manages Plugins within a namespace discovered by a PluginFinder. The default mechanism is to resolve plugins from
    entry points using a StevedorePluginFinder.

    A Plugin that is managed by a PluginManager can be in three states:
        * resolved: the entrypoint pointing to the PluginSpec was imported and the PluginSpec instance was created
        * init: the PluginFactory of the PluginSpec was successfully invoked
        * loaded: the load method of the Plugin was successfully invoked

    Internally, the PluginManager uses PluginContainer instances to keep the state of Plugin instances.
    """

    namespace: str

    load_args: Union[List, Tuple]
    load_kwargs: Dict[str, Any]
    listener: PluginLifecycleListener

    def __init__(
        self,
        namespace: str,
        load_args: Union[List, Tuple] = None,
        load_kwargs: Dict = None,
        listener: PluginLifecycleListener = None,
        finder: PluginFinder = None,
    ):
        self.namespace = namespace

        self.load_args = load_args or list()
        self.load_kwargs = load_kwargs or dict()

        self.listener = listener or PluginLifecycleListener()
        self.finder = finder or StevedorePluginFinder(
            self.namespace, self._fire_on_resolve_exception
        )

        self._plugin_index = None
        self._init_mutex = threading.RLock()

    def load(self, name: str) -> P:
        """
        Loads the Plugin with the given name using the load args and kwargs set in the plugin manager constructor.
        If at any point in the lifecycle the plugin loading fails, the load method will raise the respective exception.

        Load is idempotent, so once the plugin is loaded, load will return the same instance again.
        """
        container = self._require_plugin(name)

        if not container.is_loaded:
            self._load_plugin(container)

        if container.init_error:
            raise container.init_error

        if container.load_error:
            raise container.load_error

        if not container.is_loaded:
            raise PluginException(
                "plugin did not load correctly", namespace=self.namespace, name=name
            )

        return container.plugin

    def load_all(self, propagate_exceptions=False) -> List[P]:
        """
        Attempts to load all plugins found in the namespace, and returns those that were loaded successfully. If
        propagate_exception is set to True, then the method will re-raise any errors as soon as it encouters them.
        """
        plugins = list()

        for name, container in self._plugins.items():
            if container.is_loaded:
                plugins.append(container.plugin)
                continue

            try:
                plugin = self.load(name)
                plugins.append(plugin)
            except PluginDisabled as e:
                LOG.debug("%s", e)
            except Exception as e:
                if propagate_exceptions:
                    raise
                else:
                    LOG.error("exception while loading plugin %s:%s: %s", self.namespace, name, e)

        return plugins

    def list_plugin_specs(self) -> List[PluginSpec]:
        return [container.plugin_spec for container in self._plugins.values()]

    def list_names(self) -> List[str]:
        return [spec.name for spec in self.list_plugin_specs()]

    def list_containers(self) -> List[PluginContainer[P]]:
        return list(self._plugins.values())

    def get_container(self, name: str) -> PluginContainer[P]:
        return self._require_plugin(name)

    def exists(self, name: str) -> bool:
        return name in self._plugins

    def is_loaded(self, name: str) -> bool:
        return self._require_plugin(name).is_loaded

    @property
    def _plugins(self) -> Dict[str, PluginContainer[P]]:
        if self._plugin_index is None:
            with self._init_mutex:
                if self._plugin_index is None:
                    self._plugin_index = self._init_plugin_index()

        return self._plugin_index

    def _require_plugin(self, name: str) -> PluginContainer[P]:
        if name not in self._plugins:
            raise ValueError("no plugin named %s in namespace %s" % (name, self.namespace))

        return self._plugins[name]

    def _load_plugin(self, container: PluginContainer):
        with container.lock:
            plugin_spec = container.plugin_spec

            # instantiate Plugin from spec if necessary
            if not container.is_init:
                try:
                    LOG.debug("instantiating plugin %s", plugin_spec)
                    container.plugin = plugin_spec.factory()
                    container.is_init = True
                    self._fire_on_init_after(plugin_spec, container.plugin)
                except Exception as e:
                    # TODO: maybe we should move these logging blocks to `load_all`, since this is the only instance
                    #  where exceptions messages may get lost.
                    if LOG.isEnabledFor(logging.DEBUG):
                        LOG.exception("error instantiating plugin %s", plugin_spec)

                    self._fire_on_init_exception(plugin_spec, e)
                    container.init_error = e
                    return

            plugin = container.plugin

            if not plugin.should_load():
                raise PluginDisabled(namespace=self.namespace, name=container.plugin_spec.name)

            args = self.load_args
            kwargs = self.load_kwargs

            self._fire_on_load_before(plugin_spec, plugin, args, kwargs)
            try:
                LOG.debug("loading plugin %s:%s", self.namespace, plugin_spec.name)
                result = plugin.load(*args, *kwargs)
                self._fire_on_load_after(plugin_spec, plugin, result)
                container.load_value = result
                container.is_loaded = True
            except Exception as e:
                if LOG.isEnabledFor(logging.DEBUG):
                    LOG.exception("error loading plugin %s", plugin_spec)
                self._fire_on_load_exception(plugin_spec, plugin, e)
                container.load_error = e

    def _init_plugin_index(self) -> Dict[str, PluginContainer]:
        return {plugin.name: plugin for plugin in self._import_plugins() if plugin}

    def _import_plugins(self) -> Iterable[PluginContainer]:
        for spec in self.finder.find_plugins():
            self._fire_on_resolve_after(spec)

            if spec.namespace != self.namespace:
                continue

            yield self._create_container(spec)

    def _create_container(self, plugin_spec: PluginSpec) -> PluginContainer:
        container = PluginContainer()
        container.lock = threading.RLock()
        container.name = plugin_spec.name
        container.plugin_spec = plugin_spec
        return container


class StevedorePluginFinder(PluginFinder):
    """
    Uses a stevedore.Extension manager to resolve PluginSpec instances from entry points.
    """

    def __init__(
        self,
        namespace: str,
        on_resolve_exception_callback: Callable[[str, Any, Exception], None] = None,
        spec_resolver: PluginSpecResolver = None,
    ) -> None:
        super().__init__()
        self.namespace = namespace
        self.on_resolve_exception_callback = on_resolve_exception_callback
        self.spec_resolver = spec_resolver or PluginSpecResolver()

    def find_plugins(self) -> List[PluginSpec]:
        from stevedore import ExtensionManager
        from stevedore.exception import NoMatches

        manager = ExtensionManager(
            self.namespace,
            invoke_on_load=False,
            on_load_failure_callback=self._on_load_failure_callback,
        )

        # creates for each loadable stevedore extension a PluginSpec
        try:
            return manager.map(self.to_plugin_spec)
        except NoMatches:
            LOG.debug("no extensions found in namespace %s", self.namespace)
            return []

    def to_plugin_spec(self, ext) -> PluginSpec:
        """
        Convert a stevedore extension into a PluginSpec by using a spec_resolver.
        """
        try:
            return self.spec_resolver.resolve(ext.plugin)
        except Exception as e:
            if LOG.isEnabledFor(logging.DEBUG):
                LOG.exception(
                    "error resolving PluginSpec for plugin %s.%s", self.namespace, ext.name
                )

            self.on_resolve_exception_callback(self.namespace, ext.entry_point, e)

    def _on_load_failure_callback(self, _mgr, entrypoint, exception):
        if LOG.isEnabledFor(logging.DEBUG):
            LOG.error("error importing entrypoint %s: %s", entrypoint, exception)
        self.on_resolve_exception_callback(self.namespace, entrypoint, exception)
