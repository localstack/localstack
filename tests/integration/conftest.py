"""
Pytest configuration that spins up a single localstack instance that is shared across test modules.
See: https://docs.pytest.org/en/6.2.x/fixture.html#conftest-py-sharing-fixtures-across-multiple-files

It is thread/process safe to run with pytest-parallel, however not for pytest-xdist.
"""
import logging
import multiprocessing as mp
import os
import threading

import pytest

from localstack import config
from localstack.config import is_env_true
from localstack.constants import ENV_INTERNAL_TEST_RUN
from localstack.runtime import events
from localstack.services import infra
from localstack.utils.common import safe_requests
from tests.integration.apigateway_fixtures import create_rest_api, delete_rest_api, import_rest_api
from tests.integration.test_es import install_async as es_install_async
from tests.integration.test_opensearch import install_async as opensearch_install_async
from tests.integration.test_terraform import TestTerraform

logger = logging.getLogger(__name__)

localstack_started = mp.Event()  # event indicating whether localstack has been started
localstack_stop = mp.Event()  # event that can be triggered to stop localstack
localstack_stopped = mp.Event()  # event indicating that localstack has been stopped
startup_monitor_event = mp.Event()  # event that can be triggered to start localstack

# collection of functions that should be executed to initialize tests
test_init_functions = set()

if config.is_collect_metrics_mode():
    pytest_plugins = "localstack.testing.pytest.metric_collection"


@pytest.hookimpl()
def pytest_configure(config):
    # first pytest lifecycle hook
    _start_monitor()


def pytest_runtestloop(session):
    # second pytest lifecycle hook (before test runner starts)

    # collect test classes
    test_classes = set()
    for item in session.items:
        if item.parent and item.parent.cls:
            test_classes.add(item.parent.cls)
        # OpenSearch/Elasticsearch are pytests, not unit test classes, so we check based on the item parent's name.
        # Any pytests that rely on opensearch/elasticsearch must be special-cased by adding them to the list below
        parent_name = str(item.parent).lower()
        if any(opensearch_test in parent_name for opensearch_test in ["opensearch", "firehose"]):
            test_init_functions.add(opensearch_install_async)
        if any(opensearch_test in parent_name for opensearch_test in ["test_es", "firehose"]):
            test_init_functions.add(es_install_async)

    # add init functions for certain tests that download/install things
    for test_class in test_classes:
        # set flag that terraform will be used
        if TestTerraform is test_class:
            logger.info("will initialize TestTerraform")
            test_init_functions.add(TestTerraform.init_async)
            continue

    if not session.items:
        return

    if session.config.option.collectonly:
        return

    # trigger localstack startup in startup_monitor and wait until it becomes ready
    startup_monitor_event.set()
    localstack_started.wait()


@pytest.hookimpl()
def pytest_unconfigure(config):
    # last pytest lifecycle hook (before pytest exits)
    _trigger_stop()
    # wait for localstack to stop. We do not want to exit immediately, otherwise new threads during shutdown will fail
    if not localstack_stopped.wait(timeout=10):
        logger.warning("LocalStack did not exit in time!")


def _start_monitor():
    threading.Thread(target=startup_monitor).start()


def _trigger_stop():
    localstack_stop.set()
    startup_monitor_event.set()


def startup_monitor() -> None:
    """
    The startup monitor is a thread that waits for the startup_monitor_event and, once the event is true, starts a
    localstack instance in its own thread context.
    """
    logger.info("waiting on localstack_start signal")
    startup_monitor_event.wait()

    if localstack_stop.is_set():
        # this is called if _trigger_stop() is called before any test has requested the localstack_runtime fixture.
        logger.info("ending startup_monitor")
        localstack_stopped.set()
        return

    if is_env_true("TEST_SKIP_LOCALSTACK_START") or os.environ.get("TEST_TARGET") == "AWS_CLOUD":
        logger.info("TEST_SKIP_LOCALSTACK_START is set, not starting localstack")
        localstack_started.set()
        localstack_stopped.set()
        return

    logger.info("running localstack")
    run_localstack()


def run_localstack():
    """
    Start localstack and block until it terminates. Terminate localstack by calling _trigger_stop().
    """
    # configure
    os.environ[ENV_INTERNAL_TEST_RUN] = "1"
    safe_requests.verify_ssl = False
    config.FORCE_SHUTDOWN = False
    config.EDGE_BIND_HOST = "0.0.0.0"

    def watchdog():
        logger.info("waiting stop event")
        localstack_stop.wait()  # triggered by _trigger_stop()
        logger.info("stopping infra")
        infra.stop_infra()

    monitor = threading.Thread(target=watchdog)
    monitor.start()

    logger.info("starting localstack infrastructure")
    infra.start_infra(asynchronous=True)

    for fn in test_init_functions:
        try:
            # asynchronous init functions
            fn()
        except Exception:
            logger.exception("exception while running init function for test")

    logger.info("waiting for infra to be ready")
    events.infra_ready.wait()  # wait for infra to start (threading event)
    localstack_started.set()  # set conftest inter-process Event

    logger.info("waiting for shutdown")
    try:
        logger.info("waiting for watchdog to join")
        monitor.join()
    finally:
        logger.info("ok bye")
        localstack_stopped.set()


@pytest.fixture(scope="session", autouse=True)
def localstack_runtime():
    """
    This is a dummy fixture. Each test requests the fixture, but it actually just makes sure that localstack is running,
    blocks until localstack is running, or starts localstack the first time the fixture is requested.
    It doesn't actually do anything but signal to the `startup_monitor` function.
    """
    if localstack_started.is_set():
        # called by all tests after the startup has completed and the initial tests are unblocked
        yield
        return

    startup_monitor_event.set()
    localstack_started.wait()
    yield
    return


@pytest.fixture
def create_rest_apigw(apigateway_client):
    rest_api_ids = []

    def _create_apigateway_function(*args, **kwargs):
        api_id, name, root_id = create_rest_api(apigateway_client, **kwargs)
        rest_api_ids.append(api_id)
        return api_id, name, root_id

    yield _create_apigateway_function

    for rest_api_id in rest_api_ids:
        delete_rest_api(apigateway_client, restApiId=rest_api_id)


@pytest.fixture
def import_apigw(apigateway_client):
    rest_api_ids = []

    def _import_apigateway_function(*args, **kwargs):
        response, root_id = import_rest_api(apigateway_client, **kwargs)
        rest_api_ids.append(response.get("id"))
        return response, root_id

    yield _import_apigateway_function

    for rest_api_id in rest_api_ids:
        delete_rest_api(apigateway_client, restApiId=rest_api_id)
