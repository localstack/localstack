import os
from typing import TYPE_CHECKING

import pytest
from _pytest.config import PytestPluginManager
from _pytest.config.argparsing import Parser

if TYPE_CHECKING:
    from localstack.testing.snapshots import SnapshotSession

os.environ["LOCALSTACK_INTERNAL_TEST_RUN"] = "1"

pytest_plugins = [
    "localstack.testing.pytest.cloudtrail_tracking",
    "localstack.testing.pytest.fixtures",
    "localstack.testing.pytest.container",
    "localstack.testing.pytest.snapshot",
    "localstack.testing.pytest.filters",
    "localstack.testing.pytest.fixture_conflicts",
    "localstack.testing.pytest.detect_thread_leakage",
    "localstack.testing.pytest.marking",
    "localstack.testing.pytest.marker_report",
    "localstack.testing.pytest.in_memory_localstack",
    "localstack.testing.pytest.validation_tracking",
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
        "only_in_docker: mark the test as running only in Docker (e.g., requires installation of system packages)",
    )
    config.addinivalue_line(
        "markers",
        "resource_heavy: mark the test as resource-heavy, e.g., downloading very large external dependencies, "
        "or requiring high amount of RAM/CPU (can be systematically sampled/optimized in the future)",
    )
    config.addinivalue_line(
        "markers",
        "aws_validated: mark the test as validated / verified against real AWS",
    )
    config.addinivalue_line(
        "markers",
        "aws_only_localstack: mark the test as inherently incompatible with AWS, e.g. when testing localstack-specific features",
    )
    config.addinivalue_line(
        "markers",
        "aws_needs_fixing: test fails against AWS but it shouldn't. Might need refactoring, additional permissions, etc.",
    )
    config.addinivalue_line(
        "markers",
        "aws_manual_setup_required: validated against real AWS but needs additional setup or account configuration (e.g. increased service quotas)",
    )
    config.addinivalue_line(
        "markers",
        "aws_unknown: it's unknown if the test works (reliably) against AWS or not",
    )
    config.addinivalue_line(
        "markers",
        "multiruntime: parametrize test against multiple Lambda runtimes",
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


@pytest.fixture(scope="function")
def snapshot(_snapshot_session: "SnapshotSession"):
    return _snapshot_session


@pytest.fixture(scope="session")
def aws_session():
    """
    This fixture returns the Boto Session instance for testing.
    """
    from localstack.testing.aws.util import base_aws_session

    return base_aws_session()


@pytest.fixture(scope="session")
def aws_client_factory(aws_session):
    """
    This fixture returns a client factory for testing.

    Use this fixture if you need to use custom endpoint or Boto config.
    """
    from localstack.testing.aws.util import base_aws_client_factory

    return base_aws_client_factory(aws_session)


@pytest.fixture(scope="session")
def aws_client(aws_client_factory):
    """
    This fixture can be used to obtain Boto clients for testing.

    The clients are configured with the primary testing credentials.
    """
    from localstack.testing.aws.util import primary_testing_aws_client

    return primary_testing_aws_client(aws_client_factory)


@pytest.fixture(scope="session")
def secondary_aws_client(aws_client_factory):
    """
    This fixture can be used to obtain Boto clients for testing.

    The clients are configured with the secondary testing credentials.
    """
    from localstack.testing.aws.util import secondary_testing_aws_client

    return secondary_testing_aws_client(aws_client_factory)
