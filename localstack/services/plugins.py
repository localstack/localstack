import abc
import functools
import logging
import threading
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from enum import Enum
from typing import Callable, Dict, List, Optional, Tuple

from readerwriterlock import rwlock
from requests.models import Request

from localstack import config
from localstack.config import ServiceProviderConfig
from localstack.plugin import Plugin, PluginLifecycleListener, PluginManager, PluginSpec
from localstack.utils.bootstrap import canonicalize_api_names, log_duration
from localstack.utils.common import poll_condition

# set up logger
LOG = logging.getLogger(__name__)

# namespace for AWS provider plugins
PLUGIN_NAMESPACE = "localstack.aws.provider"


# ---------------------------
# STATE SERIALIZER INTERFACE
# ---------------------------


class PersistenceContext:
    state_dir: str
    lock: rwlock.RWLockable

    def __init__(self, state_dir: str = None, lock: rwlock.RWLockable = None):
        # state dir (within DATA_DIR) of currently processed API in local file system
        self.state_dir = state_dir
        # read-write lock for concurrency control of incoming requests
        self.lock = lock


class StateSerializer(abc.ABC):
    """A state serializer encapsulates the logic of persisting and loading service state to/from disk."""

    @abc.abstractmethod
    def restore_state(self, context: PersistenceContext):
        """Restore state from the underlying persistence file"""
        pass

    @abc.abstractmethod
    def update_state(self, context: PersistenceContext, request: Request):
        """Update persistence state based on the incoming request"""
        pass

    @abc.abstractmethod
    def is_write_request(self, request: Request) -> bool:
        """Returns whether the given request is a write request that should trigger serialization"""
        return False

    def get_lock_for_request(self, request: Request) -> Optional[rwlock.Lockable]:
        """Returns a lock (or None) that should be used to guard the given request, for concurrency control"""
        return None

    def get_context(self) -> PersistenceContext:
        """Returns the current persistence context"""
        return None


class StateSerializerComposite(StateSerializer):
    """Composite state serializer that delegates the requests to a list of underlying concrete serializers"""

    def __init__(self, serializers: List[StateSerializer] = None):
        self.serializers: List[StateSerializer] = serializers or []

    def restore_state(self, context: PersistenceContext):
        for serializer in self.serializers:
            serializer.restore_state(context)

    def update_state(self, context: PersistenceContext, request: Request):
        for serializer in self.serializers:
            serializer.update_state(context, request)

    def is_write_request(self, request: Request) -> bool:
        return any(ser.is_write_request(request) for ser in self.serializers)

    def get_lock_for_request(self, request: Request) -> Optional[rwlock.Lockable]:
        if self.serializers:
            return self.serializers[0].get_lock_for_request(
                request
            )  # return lock from first serializer

    def get_context(self) -> PersistenceContext:
        if self.serializers:
            return self.serializers[0].get_context()  # return context from first serializer


# maps service names to serializers (TODO: to be encapsulated in ServicePlugin instances)
SERIALIZERS: Dict[str, StateSerializer] = {}


# -----------------
# PLUGIN UTILITIES
# -----------------


class ServiceException(Exception):
    pass


class ServiceDisabled(ServiceException):
    pass


class ServiceStateException(ServiceException):
    pass


class Service(object):
    def __init__(self, name, start, check=None, listener=None, active=False, stop=None):
        self.plugin_name = name
        self.start_function = start
        self.listener = listener
        self.check_function = check
        self.default_active = active
        self.stop_function = stop

    def start(self, asynchronous):
        kwargs = {"asynchronous": asynchronous}
        if self.listener:
            kwargs["update_listener"] = self.listener
        return self.start_function(**kwargs)

    def stop(self):
        if not self.stop_function:
            return
        return self.stop_function()

    def check(self, expect_shutdown=False, print_error=False):
        if not self.check_function:
            return
        return self.check_function(expect_shutdown=expect_shutdown, print_error=print_error)

    def name(self):
        return self.plugin_name

    def is_enabled(self, api_names=None):
        if self.default_active:
            return True
        if api_names is None:
            api_names = canonicalize_api_names()
        return self.name() in api_names


class ServiceState(Enum):
    UNKNOWN = "unknown"
    AVAILABLE = "available"
    DISABLED = "disabled"
    STARTING = "starting"
    RUNNING = "running"
    STOPPING = "stopping"
    STOPPED = "stopped"
    ERROR = "error"


class Journal:
    name: str


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
        self.errors = list()

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
        self._services = dict()
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
        return any([self.check(service_name) for service_name in self.list_available()])

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

        with container.lock:
            if container.state == ServiceState.DISABLED:
                raise ServiceDisabled("service %s is disabled" % name)

            if container.state == ServiceState.RUNNING:
                return container.service

            if container.state == ServiceState.ERROR:
                # raise any capture error
                raise container.errors[-1]

            if container.state == ServiceState.AVAILABLE:
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
        self.errors = errors or dict()

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
    lock_dict_lock: threading.RLock
    lock_dict: Dict[str, threading.RLock]

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
            if self.provider_config.get_provider(service) in providers
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
        if self.plugin_errors.has_errors(name):
            return ServiceState.ERROR

        return ServiceState.AVAILABLE

    def get_service_container(self, name: str) -> Optional[ServiceContainer]:
        container = super().get_service_container(name)
        if container:
            return container

        if not self.exists(name):
            return None

        # this is where we start lazy loading. we now know the PluginSpec for the API exists,
        # but the ServiceContainer has not been created
        plugin = self._load_service_plugin(name)
        if not plugin or not plugin.service:
            return None

        with self._mutex:
            if plugin.service not in self._services:
                super().add_service(plugin.service)

        return super().get_service_container(name)

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

        preferred_provider = self.provider_config.get_provider(name)
        if preferred_provider in providers:
            provider = preferred_provider
        else:
            LOG.warning(
                "Configured provider (%s) does not exist for service (%s). Available options are: %s",
                preferred_provider,
                name,
                providers,
            )
            return None

        plugin_name = f"{name}:{provider}"
        service = self.plugin_manager.load(plugin_name)

        return service

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
        apis = list()
        for api, providers in self.api_provider_specs.items():
            if provider in providers:
                apis.append(api)
        return apis

    def stop_services(self, services: List[str] = None):
        """
        Stops services for this service manager, if they are currently active.
        Will not stop services not already started or in and error state.

        :param services: Service names to stop. If not provided, all services for this manager will be stopped.
        """
        for service_name in services:
            if self.get_state(service_name) in [ServiceState.STARTING, ServiceState.RUNNING]:
                service_container = self.get_service_container(service_name)
                service_container.stop()

    def stop_all_services(self) -> None:
        """
        Stops all services for this service manager, if they are currently active.
        Will not stop services not already started or in and error state.
        """
        services = self.list_available()
        self.stop_services(services)


# map of service plugins, mapping from service name to plugin details
SERVICE_PLUGINS: ServicePluginManager = ServicePluginManager()


# -------------------------
# HEALTH CHECK API METHODS
# -------------------------


def get_services_health(reload=False):
    if reload:
        SERVICE_PLUGINS.check_all()

    result = {
        "services": {
            service: state.value for service, state in SERVICE_PLUGINS.get_states().items()
        }
    }
    return result


# -----------------------------
# INFRASTRUCTURE HEALTH CHECKS
# -----------------------------


def wait_for_infra_shutdown(apis=None):
    apis = apis or canonicalize_api_names()

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
