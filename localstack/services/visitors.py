import logging
from functools import singledispatchmethod
from typing import Any, Dict, TypedDict

from moto.core import BackendDict

from localstack.persistence.core import StateVisitor
from localstack.services.stores import AccountRegionBundle

LOG = logging.getLogger(__name__)


class ServiceBackend(TypedDict, total=False):
    """Wrapper of the possible type of backends that a service can use."""

    localstack: AccountRegionBundle | None
    moto: BackendDict | Dict | None


class ServiceBackendCollectorVisitor(StateVisitor):
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
