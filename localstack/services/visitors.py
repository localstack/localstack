import importlib
import logging
from functools import singledispatchmethod
from typing import Any, Dict, List, Optional, Protocol, TypedDict, runtime_checkable

from moto.core import BackendDict

from localstack.services.stores import AccountRegionBundle

LOG = logging.getLogger(__name__)


class StateVisitor(Protocol):
    def visit(self, state_container: Any):
        """
        Visit (=do something with) a given state container. A state container can be anything that holds service state.
        An AccountRegionBundle, a moto BackendDict, or a directory containing assets.
        """
        raise NotImplementedError


@runtime_checkable
class StateVisitable(Protocol):
    def accept(self, visitor: StateVisitor):
        """
        Accept a StateVisitor. The implementing method should call visit not necessarily on itself, but can also call
        the visit method on the state container it holds. The common case is calling visit on the stores of a provider.
        :param visitor: the StateVisitor
        """


class ServiceBackend(TypedDict, total=False):
    """Wrapper of the possible type of backends that a service can use."""

    localstack: AccountRegionBundle | None
    moto: BackendDict | Dict | None


class ServiceBackendCollectorVisitor:
    """Implementation of StateVisitor meant to collect the backends that a given service use to hold its state."""

    store: AccountRegionBundle | None
    backend_dict: BackendDict | Dict | None

    def __init__(self) -> None:
        self.store = None
        self.backend_dict = None

    @singledispatchmethod
    def visit(self, state_container: Any):
        raise NotImplementedError("Can't restore state container of type %s", type(state_container))

    @visit.register(AccountRegionBundle)
    def _(self, state_container: AccountRegionBundle):
        self.store = state_container

    @visit.register(BackendDict)
    def _(self, state_container: BackendDict):
        self.backend_dict = state_container

    def collect(self) -> ServiceBackend:
        service_backend = ServiceBackend()
        if self.store:
            service_backend.update({"localstack": self.store})
        if self.backend_dict:
            service_backend.update({"moto": self.backend_dict})
        return service_backend


def _load_attribute_from_module(module_name: str, attribute_name: str) -> Any | None:
    """
    Attempts at getting an attribute from a given module.
    :return the attribute or None, if the attribute can't be found
    """
    try:
        module = importlib.import_module(module_name)
        return getattr(module, attribute_name)
    except (ModuleNotFoundError, AttributeError) as e:
        LOG.debug(
            'Unable to get attribute "%s" for module "%s": "%s"', attribute_name, module_name, e
        )
        return None


def _load_attributes(module_names: List[str], attribute_names: List[str]) -> List:
    attributes = []
    for _module, _attribute in zip(module_names, attribute_names):
        attribute = _load_attribute_from_module(_module, _attribute)
        if attribute:
            attributes.append(attribute)
    return attributes


class ReflectionStateLocator:
    """
    Implementation of the StateVisitable protocol that uses reflection to visit and collect anything that hold state
    for a service, based on the assumption that AccountRegionBundle and BackendDict are stored in a predictable
    location with a predictable naming.
    """

    provider: Any

    def __init__(self, provider: Optional[Any] = None, service: Optional[str] = None):
        self.provider = provider
        self.service = service or provider.service

    def accept(self, visitor: StateVisitor):
        # needed for services like cognito-idp
        service_name: str = self.service.replace("-", "_")

        def _visit_modules(_modules):
            for _module, _attribute in _modules:
                _attribute = _load_attribute_from_module(_module, _attribute)
                if _attribute is not None:
                    LOG.debug("Visiting attribute %s in module %s", _attribute, _module)
                    visitor.visit(_attribute)

        match service_name:
            # lambda is a special case in package and module naming
            # the store attribute is `awslambda_stores` in `localstack.services.awslambda.lambda_models`
            case "lambda":
                modules = [
                    ("localstack.services.awslambda.lambda_models", "awslambda_stores"),
                    ("moto.awslambda.models", "lambda_backends"),
                ]
                _visit_modules(modules)
            case "apigatewayv2":
                modules = [
                    ("localstack_ext.services.apigateway.models", "apigatewayv2_stores"),
                    ("moto.apigatewayv2.models", "apigatewayv2_backends"),
                ]
                _visit_modules(modules)
            case _:
                # try to load AccountRegionBundle from predictable location
                attribute_name = f"{service_name}_stores"
                module_name = f"localstack_ext.services.{service_name}.models"

                # it first looks for a module in ext; eventually, it falls back to community
                attribute = _load_attribute_from_module(module_name, attribute_name)
                if attribute is None:
                    module_name = f"localstack.services.{service_name}.models"
                    attribute = _load_attribute_from_module(module_name, attribute_name)

                if attribute is not None:
                    LOG.debug("Visiting attribute %s in module %s", attribute_name, module_name)
                    visitor.visit(attribute)

                # try to load BackendDict from predictable location
                module_name = f"moto.{service_name}.models"
                attribute_name = f"{service_name}_backends"
                attribute = _load_attribute_from_module(module_name, attribute_name)

                if attribute is not None:
                    LOG.debug("Visiting attribute %s in module %s", attribute_name, module_name)
                    visitor.visit(attribute)
