import dill
from moto.core import BackendDict

from localstack.services.stores import AccountRegionBundle
from localstack.state.inspect import ReflectionStateLocator, ServiceBackendCollectorVisitor

PersistenceBackend = AccountRegionBundle | BackendDict | dict


class StorePoliceResult:
    """
    Encapsulate the result of a store police check for a service.
    We check both the LocalStack and the moto backend.
    A control is passed if both the backends can be pickled.
    """

    service: str
    backend_checks: dict[str, tuple[bool, str | None]]

    def __init__(self, service: str) -> None:
        self.service = service
        self.backend_checks = {}

    @property
    def ok(self) -> bool:
        _ok = True
        for k, v in self.backend_checks.items():
            _ok &= v[0]
        return _ok

    @property
    def why(self) -> str | None:
        if self.ok:
            return
        _repr = ""
        for k, v in self.backend_checks.items():
            if message := v[1]:
                _repr = f"{_repr}{k} ==> {message}\n"
        return _repr

    def add(self, backend: str, backend_check: tuple[bool, str | None]):
        self.backend_checks[backend] = backend_check


class StorePolice:

    service: str
    visitor: ServiceBackendCollectorVisitor
    state_manager: ReflectionStateLocator

    def __init__(self, service: str) -> None:
        self.service = service
        self.visitor = ServiceBackendCollectorVisitor()
        self.state_manager = ReflectionStateLocator(service=service)

    def yield_backends(self) -> tuple[str, PersistenceBackend]:
        """
        Yield the backends for a given service by using the visitors.
        It yields a tuple where the first element is the backend type (localstack or moto) and the second one is the
        actual backend.
        TODO: revisit this logic upon completion of the visitors refactoring
        """
        self.state_manager.accept_state_visitor(self.visitor)
        backends = self.visitor.collect()
        for backend_type in backends:
            _backend: PersistenceBackend = backends[backend_type]  # noqa
            yield backend_type, _backend

    def control(self) -> StorePoliceResult:
        """
        Check if the backends for a given service can be pickled.
        :return StorePoliceResult
        """
        police_result = StorePoliceResult(self.service)

        for backend_type, backend in self.yield_backends():
            pickles: bool = self._pickles(backend)
            if not pickles:
                bad_types = dill.detect.badtypes(backend, depth=1)

            police_result.add(
                backend=backend_type,
                backend_check=(pickles, bad_types if not pickles else None),  # noqa
            )

        return police_result

    @staticmethod
    def _pickles(backend: PersistenceBackend) -> bool:
        return dill.pickles(backend)
