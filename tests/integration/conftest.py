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
from localstack.constants import ENV_INTERNAL_TEST_RUN
from localstack.services import infra
from localstack.utils.analytics.profiler import profiled
from localstack.utils.common import safe_requests
from tests.integration.test_terraform import TestTerraform

logger = logging.getLogger(__name__)

localstack_started = mp.Event()  # event indicating whether localstack has been started
localstack_stop = mp.Event()  # event that can be triggered to stop localstack
localstack_stopped = mp.Event()  # event indicating that localstack has been stopped
startup_monitor_event = mp.Event()  # event that can be triggered to start localstack
will_run_terraform_tests = mp.Event()  # flag to indicate that terraform should be initialized


@pytest.hookimpl()
def pytest_configure(config):
    # first pytest lifecycle hook
    _start_monitor()


def pytest_runtestloop(session):
    # second pytest lifecycle hook (before test runner starts)
    for item in session.items:
        # set flag that terraform will be used
        if 'terraform' in str(item.parent).lower():
            will_run_terraform_tests.set()
            break

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


def _start_monitor():
    threading.Thread(target=startup_monitor).start()


def _trigger_stop():
    localstack_stop.set()
    startup_monitor_event.set()


def startup_monitor() -> None:
    """
    The startup monitor is a thread that waits for the startup_monitor_event and, once the event is true, starts a
    localstack instance in it's own thread context.
    """
    logger.info('waiting on localstack_start signal')
    startup_monitor_event.wait()

    if localstack_stop.is_set():
        # this is called if _trigger_stop() is called before any test has requested the localstack_runtime fixture.
        logger.info('ending startup_monitor')
        localstack_stopped.set()
        return

    logger.info('running localstack')
    run_localstack()


def run_localstack():
    """
    Start localstack and block until it terminates. Terminate localstack by calling _trigger_stop().
    """
    # configure
    os.environ[ENV_INTERNAL_TEST_RUN] = '1'
    safe_requests.verify_ssl = False
    config.FORCE_SHUTDOWN = False

    def watchdog():
        logger.info('waiting stop event')
        localstack_stop.wait()  # triggered by _trigger_stop()
        logger.info('stopping infra')
        infra.stop_infra()

    def start_profiling(*args):
        if not config.USE_PROFILER:
            return

        @profiled()
        def profile_func():
            # keep profiler active until tests have finished
            localstack_stopped.wait()

        print('Start profiling...')
        profile_func()
        print('Done profiling...')

    monitor = threading.Thread(target=watchdog)
    monitor.start()

    logger.info('starting localstack infrastructure')
    infra.start_infra(asynchronous=True)

    threading.Thread(target=start_profiling).start()

    if will_run_terraform_tests.is_set():
        logger.info('running terraform init')
        # init terraform binary if necessary
        TestTerraform.init_async()

    logger.info('waiting for infra to be ready')
    infra.INFRA_READY.wait()  # wait for infra to start (threading event)
    localstack_started.set()  # set conftest inter-process Event

    logger.info('waiting for shutdown')
    try:
        logger.info('waiting for watchdog to join')
        monitor.join()
    finally:
        logger.info('ok bye')
        localstack_stopped.set()


@pytest.fixture(scope='session', autouse=True)
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
