import os

import dill
import pytest
from _pytest.config import PytestPluginManager
from _pytest.config.argparsing import Parser

from localstack.services.visitors import ReflectionStateLocator, ServiceBackendCollectorVisitor
from localstack.utils.analytics import log

os.environ["LOCALSTACK_INTERNAL_TEST_RUN"] = "1"

pytest_plugins = [
    "localstack.testing.pytest.fixtures",
    "localstack.testing.pytest.snapshot",
    "localstack.testing.pytest.filters",
    "localstack.testing.pytest.fixture_conflicts",
    "localstack.testing.pytest.detect_thread_leakage",
]


@pytest.hookimpl
def pytest_addoption(parser: Parser, pluginmanager: PytestPluginManager):
    parser.addoption(
        "--offline",
        action="store_true",
        default=False,
        help="test run will not have an internet connection",
    )


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "skip_offline: mark the test to be skipped when the tests are run offline "
        "(this test explicitly / semantically needs an internet connection)",
    )
    config.addinivalue_line(
        "markers",
        "aws_validated: mark the test as validated / verified against real AWS",
    )


def pytest_collection_modifyitems(config, items):
    if not config.getoption("--offline"):
        # The tests are not executed offline, so we don't skip the tests marked to need an internet connection
        return
    skip_offline = pytest.mark.skip(
        reason="Test cannot be executed offline / in a restricted network environment. "
        "Add network connectivity and remove the --offline option when running "
        "the test."
    )

    for item in items:
        if "skip_offline" in item.keywords:
            item.add_marker(skip_offline)


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_teardown(item, *args):
    # simple heuristic to get the service under test; we might want to pickle only for a single store to keep the
    # overhead limited
    import traceback

    module_name: str = item.module.__name__
    service_name = module_name.split("_")[-1]

    # todo: revisit when the visitors have been reworked
    try:
        visitor = ServiceBackendCollectorVisitor()
        state_manager = ReflectionStateLocator(service=service_name)
        state_manager.accept(visitor=visitor)
        backends = visitor.collect()
    except Exception:
        backends = []

    for backend_type in backends:
        backend = backends[backend_type]  # noqa
        try:
            dill.dumps(backend)
        except TypeError:
            print(f'Cannot pickle {backend_type} backend for {service_name}')
            log.event(
                event="pickle:error",
                backend=backend_type,
                service=service_name,
                error=traceback.format_exc(),
            )

    yield
