import logging
from typing import Any, Protocol, Union, runtime_checkable

from .skeleton import Skeleton, create_skeleton

# set up logger
LOG = logging.getLogger(__name__)

# namespace for AWS provider plugins
SERVICE_PROVIDER_NAMESPACE = "localstack.aws.provider"

_default = object()  # sentinel object indicating a default value


class StateVisitor:
    def visit(self, state_container: Any):
        """
        Visit (=do something with) a given state container. A state container can be anything that holds service state.
        An AccountRegionBundle, a moto BackendDict, or a directory containing assets.
        """
        raise NotImplementedError


@runtime_checkable
class StateVisitable(Protocol):
    def accept_state_visitor(self, visitor: StateVisitor):
        """
        Accept a StateVisitor. The implementing method should call visit not necessarily on itself, but can also call
        the visit method on the state container it holds. The common case is calling visit on the stores of a provider.

        :param visitor: the StateVisitor
        """


class StateLifecycleHook:
    def on_after_state_reset(self):
        pass

    def on_after_state_inject(self):
        pass


@runtime_checkable
class ServiceHealthCheck(Protocol):
    def is_service_healthy(self) -> bool:
        ...


class ServiceLifecycleHook:
    def on_after_init(self):
        pass

    def on_before_start(self):
        pass

    def on_before_stop(self):
        pass

    def on_exception(self):
        pass


class ServiceApi(Protocol):
    service: str
    version: str


class _NoopHealthCheck:
    def is_service_healthy(self):
        return True


class _NoopStateVisitable:
    def accept_state_visitor(self, visitor: StateVisitor):
        pass


class ServiceProvider:
    """
    Holds a provider, the underlying skeleton, and the various lifecycle hooks to interact with it.
    """

    implementation: ServiceApi
    skeleton: Skeleton
    service: str

    state_visitable: StateVisitable
    service_lifecycle_hook: ServiceLifecycleHook
    state_lifecycle_hook: StateLifecycleHook
    service_health_check: ServiceHealthCheck

    def __init__(
        self,
        implementation: Union[ServiceApi, object],
        service: str = None,
        skeleton: Skeleton = None,
        service_lifecycle_hook: ServiceLifecycleHook = None,
        state_lifecycle_hook: StateLifecycleHook = None,
        service_health_check: ServiceHealthCheck = None,
        state_visitable: StateVisitable = None,
    ):
        self.implementation = implementation
        self.service = service or implementation.service
        self.skeleton = skeleton or self._create_skeleton(implementation)

        if service_lifecycle_hook:
            self.service_lifecycle_hook = service_lifecycle_hook
        else:
            if isinstance(implementation, ServiceLifecycleHook):
                self.service_lifecycle_hook = implementation
            else:
                self.service_lifecycle_hook = ServiceLifecycleHook()  # noop

        if state_lifecycle_hook:
            self.state_lifecycle_hook = state_lifecycle_hook
        else:
            if isinstance(implementation, StateLifecycleHook):
                self.state_lifecycle_hook = implementation
            else:
                self.state_lifecycle_hook = StateLifecycleHook()

        if service_health_check:
            self.service_health_check = service_health_check
        else:
            if isinstance(implementation, ServiceHealthCheck):
                self.service_health_check = implementation
            else:
                self.service_health_check = self._create_default_service_health_check()

        if state_visitable:
            self.state_visitable = state_visitable
        else:
            if isinstance(implementation, StateVisitable):
                self.state_visitable = implementation
            else:
                self.state_visitable = self._create_default_state_visitable()

    def _create_skeleton(self, provider: ServiceApi) -> Skeleton:
        return create_skeleton(provider.service, provider)

    def _create_default_state_visitable(self) -> StateVisitable:
        return _NoopStateVisitable()

    def _create_default_service_health_check(self) -> ServiceHealthCheck:
        return _NoopHealthCheck()
