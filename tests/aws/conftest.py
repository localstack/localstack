import logging
import os
from typing import Optional

import pytest
from _pytest.config import Config
from _pytest.reports import TestReport
from _pytest.terminal import TerminalReporter

from localstack import config as localstack_config
from localstack import constants
from localstack.testing.scenario.provisioning import InfraProvisioner
from tests.aws.test_terraform import TestTerraform

LOG = logging.getLogger(__name__)


def pytest_configure(config: Config):
    # FIXME: note that this should be the same as in tests/integration/conftest.py since both are currently
    #  run in the same CI test step, but only one localstack instance is started for both.
    config.option.start_localstack = True
    localstack_config.FORCE_SHUTDOWN = False
    localstack_config.GATEWAY_LISTEN = localstack_config.UniqueHostAndPortList(
        [localstack_config.HostAndPort(host="0.0.0.0", port=constants.DEFAULT_PORT_EDGE)]
    )


def pytest_runtestloop(session):
    # second pytest lifecycle hook (before test runner starts)
    test_init_functions = set()

    # collect test classes
    test_classes = set()
    for item in session.items:
        if item.parent and item.parent.cls:
            test_classes.add(item.parent.cls)
        # OpenSearch/Elasticsearch are pytests, not unit test classes, so we check based on the item parent's name.
        # Any pytests that rely on opensearch/elasticsearch must be special-cased by adding them to the list below
        parent_name = str(item.parent).lower()
        if any(opensearch_test in parent_name for opensearch_test in ["opensearch", "firehose"]):
            from tests.aws.services.opensearch.test_opensearch import (
                install_async as opensearch_install_async,
            )

            test_init_functions.add(opensearch_install_async)
        if any(opensearch_test in parent_name for opensearch_test in ["test_es", "firehose"]):
            from tests.aws.services.es.test_es import install_async as es_install_async

            test_init_functions.add(es_install_async)

    # add init functions for certain tests that download/install things
    for test_class in test_classes:
        # set flag that terraform will be used
        if TestTerraform is test_class:
            test_init_functions.add(TestTerraform.init_async)
            continue

    if not session.items:
        return

    if session.config.option.collectonly:
        return

    for fn in test_init_functions:
        fn()


# Note: Don't move this into testing lib
@pytest.fixture(scope="session")
def cdk_template_path():
    return os.path.abspath(os.path.join(os.path.dirname(__file__), "cdk_templates"))


# Note: Don't move this into testing lib
@pytest.fixture(scope="session")
def infrastructure_setup(cdk_template_path, aws_client):
    def _infrastructure_setup(
        namespace: str, force_synth: Optional[bool] = False
    ) -> InfraProvisioner:
        """
        :param namespace: repo-unique identifier for this CDK app.
            A directory with this name will be created at `tests/aws/cdk_templates/<namespace>/`
        :param force_synth: set to True to always re-synth the CDK app
        :return: an instantiated CDK InfraProvisioner which can be used to deploy a CDK app
        """
        return InfraProvisioner(
            base_path=cdk_template_path,
            aws_client=aws_client,
            namespace=namespace,
            force_synth=force_synth,
            persist_output=True,
        )

    return _infrastructure_setup


# capture test information
def pytest_runtest_logstart(nodeid: str, location: tuple[str, int | None, str]):
    from localstack.aws.handlers import capture_test_resource_lifetimes

    capture_test_resource_lifetimes.set_test(nodeid)


def pytest_runtest_logreport(report: TestReport):
    from localstack.aws.handlers import capture_test_resource_lifetimes

    capture_test_resource_lifetimes.last_report = report


def pytest_runtest_logfinish(nodeid: str, location: tuple[str, int | None, str]):
    from localstack.aws.handlers import capture_test_resource_lifetimes

    capture_test_resource_lifetimes.end_test()


def pytest_terminal_summary(terminalreporter: TerminalReporter, exitstatus: int, config: Config):
    from localstack.aws.handlers import capture_test_resource_lifetimes

    capture_test_resource_lifetimes.terminal_report(terminalreporter)
