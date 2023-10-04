import abc
import functools
import logging
import threading
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from enum import Enum
from typing import Callable, Dict, List, Optional, Protocol, Tuple

from plugin import Plugin, PluginLifecycleListener, PluginManager, PluginSpec

from localstack import config
from localstack.aws.skeleton import DispatchTable
from localstack.config import ServiceProviderConfig
from localstack.state import StateLifecycleHook, StateVisitable, StateVisitor
from localstack.utils.bootstrap import get_enabled_apis, log_duration
from localstack.utils.functions import call_safe
from localstack.utils.net import wait_for_port_status
from localstack.utils.sync import SynchronizedDefaultDict, poll_condition

# set up logger
LOG = logging.getLogger(__name__)

# namespace for AWS provider plugins
PLUGIN_NAMESPACE = "localstack.aws.provider"

_default = object()  # sentinel object indicating a default value


# -----------------
# PLUGIN UTILITIES
# -----------------


class ServiceException(Exception):
    pass


class ServiceDisabled(ServiceException):
    pass


class ServiceStateException(ServiceException):
    pass


class ServiceLifecycleHook(StateLifecycleHook):
    def on_after_init(self):
        pass

    def on_before_start(self):
        pass

    def on_before_stop(self):
        pass

    def on_exception(self):
        pass


class ServiceProvider(Protocol):
    service: str


class Service:
    """
    FIXME: this has become frankenstein's monster, and it has to go. once we've rid ourselves of the legacy edge
     proxy, we can get rid of the ``listener`` concept. we should then do one iteration over all the
     ``start_dynamodb``, ``start_<whatever>``, ``check_<whatever>``, etc. methods, to make all of those integral part
     of the service provider. the assumption that every service provider starts a backend server is outdated, and then
     we can get rid of ``start``, and ``check``.
    """

    def __init__(
        self,
        name,
        start=_default,
        check=_default,
        listener=None,
        active=False,
        stop=None,
        lifecycle_hook: ServiceLifecycleHook = None,
    ):
        self.plugin_name = name
        self.start_function = start
        self.listener = listener
        self.check_function = check if check is not _default else local_api_checker(name)
        self.default_active = active
        self.stop_function = stop
        self.lifecycle_hook = lifecycle_hook or ServiceLifecycleHook()
        self._provider = None
        call_safe(self.lifecycle_hook.on_after_init)

    def start(self, asynchronous):
        call_safe(self.lifecycle_hook.on_before_start)

        if not self.start_function:
            return

        if self.start_function is _default:
            # fallback start method that simply adds the listener function to the list of proxy listeners if it exists
            if not self.listener:
                return

            from localstack.services.infra import add_service_proxy_listener

            add_service_proxy_listener(self.plugin_name, self.listener)
            return

        kwargs = {"asynchronous": asynchronous}
        if self.listener:
            kwargs["update_listener"] = self.listener
        return self.start_function(**kwargs)

    def stop(self):
        call_safe(self.lifecycle_hook.on_before_stop)
        if not self.stop_function:
            return
        return self.stop_function()

    def check(self, expect_shutdown=False, print_error=False):
        if not self.check_function:
            return
        return self.check_function(expect_shutdown=expect_shutdown, print_error=print_error)

    def name(self):
        return self.plugin_name

    def is_enabled(self):
        return True

    def accept_state_visitor(self, visitor: StateVisitor):
        """
        Passes the StateVisitor to the ASF provider if it is set and implements the StateVisitable. Otherwise, it uses
        the ReflectionStateLocator to visit the service state.

        :param visitor: the visitor
        """
        if self._provider and isinstance(self._provider, StateVisitable):
            self._provider.accept_state_visitor(visitor)
            return

        from localstack.state.inspect import ReflectionStateLocator

        ReflectionStateLocator(service=self.name()).accept_state_visitor(visitor)

    @staticmethod
    def for_provider(
        provider: ServiceProvider,
        dispatch_table_factory: Callable[[ServiceProvider], DispatchTable] = None,
        service_lifecycle_hook: ServiceLifecycleHook = None,
    ) -> "Service":
        """
        Factory method for creating services for providers. This method hides a bunch of legacy code and
        band-aids/adapters to make persistence visitors work, while providing compatibility with the legacy edge proxy.

        :param provider: the service provider, i.e., the implementation of the generated ASF service API.
        :param dispatch_table_factory: a `MotoFallbackDispatcher` or something similar that uses the provider to
            create a dispatch table. this one's a bit clumsy.
        :param service_lifecycle_hook: if left empty, the factory checks whether the provider is a ServiceLifecycleHook.
        :return: a service instance
        """
        from localstack.aws.proxy import AwsApiListener

        # determine the service_lifecycle_hook
        if service_lifecycle_hook is None:
            if isinstance(provider, ServiceLifecycleHook):
                service_lifecycle_hook = provider

        # determine the delegate for injecting into the AwsApiListener
        delegate = dispatch_table_factory(provider) if dispatch_table_factory else provider

        service = Service(
            name=provider.service,
            listener=AwsApiListener(provider.service, delegate=delegate),
            lifecycle_hook=service_lifecycle_hook,
            check=None,
        )
        service._provider = provider

        return service


class ServiceState(Enum):
    UNKNOWN = "unknown"
    AVAILABLE = "available"
    DISABLED = "disabled"
    STARTING = "starting"
    RUNNING = "running"
    STOPPING = "stopping"
    STOPPED = "stopped"
    ERROR = "error"


class ServiceContainer:
    """
    Holds a service, its state, and exposes lifecycle methods of the service.
    """

    service: Service
    state: ServiceState
    lock: threading.RLock
    errors: List[Exception]

    def __init__(self, service: Service, state=ServiceState.UNKNOWN):
        self.service = service
        self.state = state
        self.lock = threading.RLock()
        self.errors = []

    def get(self) -> Service:
        return self.service

    def start(self) -> bool:
        try:
            self.state = ServiceState.STARTING
            self.service.start(asynchronous=True)
        except Exception as e:
            self.state = ServiceState.ERROR
            self.errors.append(e)
            LOG.error("error while starting service %s: %s", self.service.name(), e)
            return False
        return self.check()

    def check(self) -> bool:
        try:
            self.service.check(print_error=True)
            self.state = ServiceState.RUNNING
            return True
        except Exception as e:
            self.state = ServiceState.ERROR
            self.errors.append(e)
            LOG.error("error while checking service %s: %s", self.service.name(), e)
            return False

    def stop(self):
        try:
            self.state = ServiceState.STOPPING
            self.service.stop()
            self.state = ServiceState.STOPPED
        except Exception as e:
            self.state = ServiceState.ERROR
            self.errors.append(e)


class ServiceManager:
    def __init__(self) -> None:
        super().__init__()
        self._services: Dict[str, ServiceContainer] = {}
        self._mutex = threading.RLock()

    def get_service_container(self, name: str) -> Optional[ServiceContainer]:
        return self._services.get(name)

    def get_service(self, name: str) -> Optional[Service]:
        container = self.get_service_container(name)
        return container.service if container else None

    def add_service(self, service: Service) -> bool:
        state = ServiceState.AVAILABLE if service.is_enabled() else ServiceState.DISABLED
        self._services[service.name()] = ServiceContainer(service, state)

        return True

    def list_available(self) -> List[str]:
        return list(self._services.keys())

    def exists(self, name: str) -> bool:
        return name in self._services

    def is_running(self, name: str) -> bool:
        return self.get_state(name) == ServiceState.RUNNING

    def check(self, name: str) -> bool:
        if self.get_state(name) in [ServiceState.RUNNING, ServiceState.ERROR]:
            return self.get_service_container(name).check()

    def check_all(self):
        return any(self.check(service_name) for service_name in self.list_available())

    def get_state(self, name: str) -> Optional[ServiceState]:
        container = self.get_service_container(name)
        return container.state if container else None

    def get_states(self) -> Dict[str, ServiceState]:
        return {name: self.get_state(name) for name in self.list_available()}

    @log_duration()
    def require(self, name: str) -> Service:
        """
        High level function that always returns a running service, or raises an error. If the service is in a state
        that it could be transitioned into a running state, then invoking this function will attempt that transition,
        e.g., by starting the service if it is available.
        """
        container = self.get_service_container(name)

        if not container:
            raise ValueError("no such service %s" % name)

        if container.state == ServiceState.STARTING:
            if not poll_condition(lambda: container.state != ServiceState.STARTING, timeout=30):
                raise TimeoutError("gave up waiting for service %s to start" % name)

        if container.state == ServiceState.STOPPING:
            if not poll_condition(lambda: container.state == ServiceState.STOPPED, timeout=30):
                raise TimeoutError("gave up waiting for service %s to stop" % name)

        with container.lock:
            if container.state == ServiceState.DISABLED:
                raise ServiceDisabled("service %s is disabled" % name)

            if container.state == ServiceState.RUNNING:
                return container.service

            if container.state == ServiceState.ERROR:
                # raise any capture error
                raise container.errors[-1]

            if container.state == ServiceState.AVAILABLE or container.state == ServiceState.STOPPED:
                if container.start():
                    return container.service
                else:
                    raise container.errors[-1]

        raise ServiceStateException(
            "service %s is not ready (%s) and could not be started" % (name, container.state)
        )

    # legacy map compatibility

    def items(self):
        return {
            container.service.name(): container.service for container in self._services.values()
        }.items()

    def keys(self):
        return self._services.keys()

    def values(self):
        return [container.service for container in self._services.values()]

    def get(self, key):
        return self.get_service(key)

    def __iter__(self):
        return self._services


class ServicePlugin(Plugin):
    service: Service
    api: str

    @abc.abstractmethod
    def create_service(self) -> Service:
        raise NotImplementedError

    def load(self):
        self.service = self.create_service()
        return self.service


class ServicePluginAdapter(ServicePlugin):
    def __init__(
        self,
        api: str,
        create_service: Callable[[], Service],
        should_load: Callable[[], bool] = None,
    ) -> None:
        super().__init__()
        self.api = api
        self._create_service = create_service
        self._should_load = should_load

    def should_load(self) -> bool:
        if self._should_load:
            return self._should_load()
        return True

    def create_service(self) -> Service:
        return self._create_service()


def aws_provider(api: str = None, name="default", should_load: Callable[[], bool] = None):
    """
    Decorator for marking methods that create a Service instance as a ServicePlugin. Methods marked with this
    decorator are discoverable as a PluginSpec within the namespace "localstack.aws.provider", with the name
    "<api>:<name>". If api is not explicitly specified, then the method name is used as api name.
    """

    def wrapper(fn):
        # sugar for being able to name the function like the api
        _api = api or fn.__name__

        # this causes the plugin framework into pointing the entrypoint to the original function rather than the
        # nested factory function
        @functools.wraps(fn)
        def factory() -> ServicePluginAdapter:
            return ServicePluginAdapter(api=_api, should_load=should_load, create_service=fn)

        return PluginSpec(PLUGIN_NAMESPACE, f"{_api}:{name}", factory=factory)

    return wrapper


class ServicePluginErrorCollector(PluginLifecycleListener):
    """
    A PluginLifecycleListener that collects errors related to service plugins.
    """

    errors: Dict[Tuple[str, str], Exception]  # keys are: (api, provider)

    def __init__(self, errors: Dict[str, Exception] = None) -> None:
        super().__init__()
        self.errors = errors or {}

    def get_key(self, plugin_name) -> Tuple[str, str]:
        # the convention is <api>:<provider>, currently we don't really expose the provider
        # TODO: faulty plugin names would break this
        return tuple(plugin_name.split(":", maxsplit=1))

    def on_resolve_exception(self, namespace: str, entrypoint, exception: Exception):
        self.errors[self.get_key(entrypoint.name)] = exception

    def on_init_exception(self, plugin_spec: PluginSpec, exception: Exception):
        self.errors[self.get_key(plugin_spec.name)] = exception

    def on_load_exception(self, plugin_spec: PluginSpec, plugin: Plugin, exception: Exception):
        self.errors[self.get_key(plugin_spec.name)] = exception

    def has_errors(self, api: str, provider: str = None) -> bool:
        for e_api, e_provider in self.errors.keys():
            if api == e_api:
                if not provider:
                    return True
                else:
                    return e_provider == provider

        return False


class ServicePluginManager(ServiceManager):
    plugin_manager: PluginManager[ServicePlugin]
    plugin_errors: ServicePluginErrorCollector

    def __init__(
        self,
        plugin_manager: PluginManager[ServicePlugin] = None,
        provider_config: ServiceProviderConfig = None,
    ) -> None:
        super().__init__()
        self.plugin_errors = ServicePluginErrorCollector()
        self.plugin_manager = plugin_manager or PluginManager(
            PLUGIN_NAMESPACE, listener=self.plugin_errors
        )
        self._api_provider_specs = None
        self.provider_config = provider_config or config.SERVICE_PROVIDER_CONFIG

        # locks used to make sure plugin loading is thread safe - will be cleared after single use
        self._plugin_load_locks: Dict[str, threading.RLock] = SynchronizedDefaultDict(
            threading.RLock
        )

    def get_active_provider(self, service: str) -> str:
        """
        Get configured provider for a given service

        :param service: Service name
        :return: configured provider
        """
        return self.provider_config.get_provider(service)

    def get_default_provider(self) -> str:
        """
        Get the default provider

        :return: default provider
        """
        return self.provider_config.default_value

    # TODO make the abstraction clearer, to provide better information if service is available versus discoverable
    # especially important when considering pro services
    def list_available(self) -> List[str]:
        """
        List all available services, which have an available, configured provider

        :return: List of service names
        """
        return [
            service
            for service, providers in self.api_provider_specs.items()
            if self.get_active_provider(service) in providers
        ]

    def _get_loaded_service_containers(
        self, services: Optional[List[str]] = None
    ) -> List[ServiceContainer]:
        """
        Returns all the available service containers.
        :param services: the list of services to restrict the search to. If empty or NULL then service containers for
                         all available services are queried.
        :return: a list of all the available service containers.
        """
        services = services or self.list_available()
        return [
            c for s in services if (c := super(ServicePluginManager, self).get_service_container(s))
        ]

    def list_loaded_services(self) -> List[str]:
        """
        Lists all the services which have a provider that has been initialized

        :return: a list of service names
        """
        return [
            service_container.service.name()
            for service_container in self._get_loaded_service_containers()
        ]

    def list_active_services(self) -> List[str]:
        """
        Lists all services that have an initialised provider and are currently running.

        :return: the list of active service names.
        """
        return [
            service_container.service.name()
            for service_container in self._get_loaded_service_containers()
            if service_container.state == ServiceState.RUNNING
        ]

    def exists(self, name: str) -> bool:
        return name in self.list_available()

    def get_state(self, name: str) -> Optional[ServiceState]:
        if name in self._services:
            # ServiceContainer exists, which means the plugin has been loaded
            return super().get_state(name)

        if not self.exists(name):
            # there's definitely no service with this name
            return None

        # if a PluginSpec exists, then we can get the container and check whether there was an error loading the plugin
        provider = self.get_active_provider(name)
        if self.plugin_errors.has_errors(name, provider):
            return ServiceState.ERROR

        return ServiceState.AVAILABLE

    def get_service_container(self, name: str) -> Optional[ServiceContainer]:
        if container := self._services.get(name):
            return container

        if not self.exists(name):
            return None

        load_lock = self._plugin_load_locks[name]
        with load_lock:
            # check once again to avoid race conditions
            if container := self._services.get(name):
                return container

            # this is where we start lazy loading. we now know the PluginSpec for the API exists,
            # but the ServiceContainer has not been created.
            # this control path will be executed once per service
            plugin = self._load_service_plugin(name)
            if not plugin or not plugin.service:
                return None

            with self._mutex:
                super().add_service(plugin.service)

            del self._plugin_load_locks[name]  # we only needed the service lock once

            return self._services.get(name)

    @property
    def api_provider_specs(self) -> Dict[str, List[str]]:
        """
        Returns all provider names within the service plugin namespace and parses their name according to the convention,
        that is "<api>:<provider>". The result is a dictionary that maps api => List[str (name of a provider)].
        """
        if self._api_provider_specs is not None:
            return self._api_provider_specs

        with self._mutex:
            if self._api_provider_specs is None:
                self._api_provider_specs = self._resolve_api_provider_specs()
            return self._api_provider_specs

    @log_duration()
    def _load_service_plugin(self, name: str) -> Optional[ServicePlugin]:
        providers = self.api_provider_specs.get(name)
        if not providers:
            # no providers for this api
            return None

        preferred_provider = self.get_active_provider(name)
        if preferred_provider in providers:
            provider = preferred_provider
        else:
            default = self.get_default_provider()
            LOG.warning(
                "Configured provider (%s) does not exist for service (%s). Available options are: %s. "
                "Falling back to default provider '%s'. This can impact the availability of Pro functionality, "
                "please fix this configuration issue as soon as possible.",
                preferred_provider,
                name,
                providers,
                default,
            )
            provider = default

        plugin_name = f"{name}:{provider}"
        plugin = self.plugin_manager.load(plugin_name)
        plugin.name = plugin_name

        return plugin

    @log_duration()
    def _resolve_api_provider_specs(self) -> Dict[str, List[str]]:
        result = defaultdict(list)

        for spec in self.plugin_manager.list_plugin_specs():
            api, provider = spec.name.split(
                ":"
            )  # TODO: error handling, faulty plugins could break the runtime
            result[api].append(provider)

        return result

    def apis_with_provider(self, provider: str) -> List[str]:
        """
        Lists all apis where a given provider exists for.
        :param provider: Name of the provider
        :return: List of apis the given provider provides
        """
        apis = []
        for api, providers in self.api_provider_specs.items():
            if provider in providers:
                apis.append(api)
        return apis

    def _stop_services(self, service_containers: List[ServiceContainer]) -> None:
        """
        Atomically attempts to stop all given 'ServiceState.STARTING' and 'ServiceState.RUNNING' services.
        :param service_containers: the list of service containers to be stopped.
        """
        target_service_states = {ServiceState.STARTING, ServiceState.RUNNING}
        with self._mutex:
            for service_container in service_containers:
                if service_container.state in target_service_states:
                    service_container.stop()

    def stop_services(self, services: List[str] = None):
        """
        Stops services for this service manager, if they are currently active.
        Will not stop services not already started or in and error state.

        :param services: Service names to stop. If not provided, all services for this manager will be stopped.
        """
        target_service_containers = self._get_loaded_service_containers(services=services)
        self._stop_services(target_service_containers)

    def stop_all_services(self) -> None:
        """
        Stops all services for this service manager, if they are currently active.
        Will not stop services not already started or in and error state.
        """
        target_service_containers = self._get_loaded_service_containers()
        self._stop_services(target_service_containers)


# map of service plugins, mapping from service name to plugin details
SERVICE_PLUGINS: ServicePluginManager = ServicePluginManager()


# -----------------------------
# INFRASTRUCTURE HEALTH CHECKS
# -----------------------------


def wait_for_infra_shutdown():
    apis = get_enabled_apis()

    names = [name for name, plugin in SERVICE_PLUGINS.items() if name in apis]

    def check(name):
        check_service_health(api=name, expect_shutdown=True)
        LOG.debug("[shutdown] api %s has shut down", name)

    # no special significance to 10 workers, seems like a reasonable number given the number of services we have
    with ThreadPoolExecutor(max_workers=10) as executor:
        executor.map(check, names)


def check_service_health(api, expect_shutdown=False):
    status = SERVICE_PLUGINS.check(api)
    if status == expect_shutdown:
        if not expect_shutdown:
            LOG.warning('Service "%s" not yet available, retrying...', api)
        else:
            LOG.warning('Service "%s" still shutting down, retrying...', api)
        raise Exception("Service check failed for api: %s" % api)


def local_api_checker(service: str) -> Callable:
    """
    Creates a health check method for the given service that works under the assumption that the real backend service
    ports are locatable through the PROXY_LISTENER global.
    """
    from localstack.services.infra import PROXY_LISTENERS

    if config.EAGER_SERVICE_LOADING:
        # most services don't have a real health check, and if they would, that would dramatically increase the
        # startup time, since health checks are done sequentially at startup. however, the health checks are needed
        # for the lazy-loading cold start.
        return lambda *args, **kwargs: None

    def _check(expect_shutdown=False, print_error=False):
        port = None
        try:
            if service not in PROXY_LISTENERS:
                LOG.debug("cannot find backend port for service %s", service)
                return
            port = PROXY_LISTENERS[service][1]

            if port is None:
                # for modern ASF services, the port can be none since the service is just served by localstack
                return

            LOG.debug("checking service health %s:%d", service, port)
            wait_for_port_status(port, expect_success=not expect_shutdown)
        except Exception:
            if print_error:
                LOG.exception("service health check %s:%s failed", service, port)

    return _check
