"""Pytest plugin that spins up a single localstack instance in the current interpreter that is shared
across the current test session.

Use in your module as follows::

    pytest_plugins = "localstack.testing.pytest.in_memory_localstack"

    @pytest.hookimpl()
    def pytest_configure(config):
        config.option.start_localstack = True

You can explicitly disable starting localstack by setting ``TEST_SKIP_LOCALSTACK_START=1`` or
``TEST_TARGET=AWS_CLOUD``."""
import logging
import os
import threading

import pytest
from _pytest.config import PytestPluginManager
from _pytest.config.argparsing import Parser
from _pytest.main import Session

from localstack import config as localstack_config
from localstack.config import is_env_true
from localstack.constants import ENV_INTERNAL_TEST_RUN

LOG = logging.getLogger(__name__)
LOG.info("Pytest plugin for in-memory-localstack session loaded.")

if localstack_config.is_collect_metrics_mode():
    pytest_plugins = "localstack.testing.pytest.metric_collection"


_started = threading.Event()


def pytest_addoption(parser: Parser, pluginmanager: PytestPluginManager):
    parser.addoption(
        "--start-localstack",
        action="store_true",
        default=False,
    )


@pytest.hookimpl(tryfirst=True)
def pytest_runtestloop(session: Session):
    if not session.config.option.start_localstack:
        return

    from localstack.testing.aws.util import is_aws_cloud

    if is_env_true("TEST_SKIP_LOCALSTACK_START") or is_aws_cloud():
        LOG.info("TEST_SKIP_LOCALSTACK_START is set, not starting localstack")
        return

    from localstack.runtime import events
    from localstack.services import infra
    from localstack.utils.common import safe_requests

    if is_aws_cloud():
        localstack_config.DEFAULT_DELAY = 5
        localstack_config.DEFAULT_MAX_ATTEMPTS = 60

    # configure
    os.environ[ENV_INTERNAL_TEST_RUN] = "1"
    safe_requests.verify_ssl = False

    _started.set()
    infra.start_infra(asynchronous=True)
    # wait for infra to start (threading event)
    if not events.infra_ready.wait(timeout=120):
        raise TimeoutError("gave up waiting for infra to be ready")


@pytest.hookimpl(trylast=True)
def pytest_sessionfinish(session: Session):
    # last pytest lifecycle hook (before pytest exits)
    if not _started.is_set():
        return

    from localstack.runtime import events
    from localstack.services import infra
    from localstack.utils.threads import start_thread

    def _stop_infra(*_args):
        LOG.info("stopping infra")
        infra.stop_infra()

    start_thread(_stop_infra)
    LOG.info("waiting for infra to stop")

    if not events.infra_stopped.wait(timeout=10):
        LOG.warning("gave up waiting for infra to stop, returning anyway")
