import dataclasses
from typing import Iterable, Optional

import pytest
from _pytest.reports import TestReport
from _pytest.runner import CallInfo
from pluggy.callers import _Result
from pytest import Item

from localstack.aws.chain import Handler
from localstack.services.plugins import SERVICE_PLUGINS, ServiceManager
from localstack.state import StateContainer, StateVisitor, pickle
from localstack.utils.objects import singleton_factory


@pytest.hookimpl()
def pytest_configure(config):
    from localstack_persistence.pickling import reducers

    from localstack.aws.handlers import serve_custom_service_request_handlers

    # register custom reducers
    reducers.register()

    # inject dirty marker into chain
    serve_custom_service_request_handlers.append(get_dirty_marker_handler())


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_call(item: Item) -> None:
    call: CallInfo = yield  # noqa

    if call.excinfo:
        return

    collector = PicklingErrorCollector(SERVICE_PLUGINS)
    marker = get_dirty_marker_handler()
    result = collector.try_pickle_state_containers(marker.dirty)
    marker.clear()

    if result.errors:
        raise PicklingTestException(result)


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item: Item, call: CallInfo[None]) -> Optional[TestReport]:
    result: _Result = yield

    report: TestReport = result.result

    if call.excinfo is not None and isinstance(call.excinfo.value, PicklingTestException):
        # FIXME: make a proper report
        err: PicklingTestException = call.excinfo.value
        report.longrepr = "\n".join([str(e) for e in err.result.errors])

    return report


@singleton_factory
def get_dirty_marker_handler():
    return DirtyMarkerHandler()


@dataclasses.dataclass
class PicklingError:
    """
    Encapsulate the result of a store police check for a service.
    We check both the LocalStack and the moto backend.
    A control is passed if both the backends can be pickled.
    """

    service: str
    state_container: StateContainer
    exception: Exception


class PicklingTestResult:
    errors: list[PicklingError]

    def __init__(self):
        self.errors = []


class PicklingTestException(Exception):
    result: PicklingTestResult

    def __init__(self, result: PicklingTestResult):
        super().__init__()
        self.result = result


class DirtyMarkerHandler(Handler):
    """
    A handler injected into the handler chain to only
    """

    def __init__(self):
        self.dirty = set()

    def __call__(self, chain, context, response):
        if not context.service:
            return

        self.dirty.add(context.service.service_name)

    def clear(self):
        self.dirty.clear()


class PicklingVisitor(StateVisitor):
    errors: list[PicklingError]

    def __init__(self, service: str):
        self.errors = []
        self.service = service

    def visit(self, state_container: StateContainer):
        try:
            pickle.dumps(state_container)
        except Exception as e:
            self.errors.append(PicklingError(self.service, state_container, e))


class PicklingErrorCollector:
    def __init__(self, service_manager: ServiceManager):
        self.service_manager = service_manager

    def try_pickle_state_containers(self, services: Iterable[str]) -> PicklingTestResult:
        result = PicklingTestResult()
        for service_name in services:

            service = self.service_manager.get_service(service_name)
            if not service:
                continue
            visitor = PicklingVisitor(service_name)
            service.accept_state_visitor(visitor)
            result.errors.extend(visitor.errors)

        return result
