"""
Pytest configuration that spins up a single localstack instance that is shared across test modules.
See: https://docs.pytest.org/en/6.2.x/fixture.html#conftest-py-sharing-fixtures-across-multiple-files

It is thread/process safe to run with pytest-parallel, however not for pytest-xdist.
"""
import logging
import os
import threading

import pytest
from _pytest.config import Config, PytestPluginManager
from _pytest.config.argparsing import Parser
from _pytest.main import Session

from localstack import config as localstack_config
from localstack import constants
from localstack.config import is_env_true
from localstack.constants import ENV_INTERNAL_TEST_RUN
from localstack.testing.aws.util import is_aws_cloud

LOG = logging.getLogger(__name__)

if localstack_config.is_collect_metrics_mode():
    pytest_plugins = "localstack.testing.pytest.metric_collection"


_started = threading.Event()


def pytest_addoption(parser: Parser, pluginmanager: PytestPluginManager):
    parser.addoption(
        "--start-localstack",
        type=bool,
    )


@pytest.hookimpl(trylast=True)
def pytest_configure(config: Config):
    localstack_config.FORCE_SHUTDOWN = False
    localstack_config.GATEWAY_LISTEN = [
        localstack_config.HostAndPort(host="0.0.0.0", port=constants.DEFAULT_PORT_EDGE)
    ]


@pytest.hookimpl(tryfirst=True)
def pytest_sessionstart(session: Session):
    if not session.config.option.start_localstack:
        return

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
