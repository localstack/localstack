import os

import boto3
import pytest
from _pytest.config import PytestPluginManager
from _pytest.config.argparsing import Parser

from localstack.testing.aws.util import (
    base_aws_client_factory,
    base_aws_session,
    primary_testing_aws_client,
    secondary_testing_aws_client,
)

os.environ["LOCALSTACK_INTERNAL_TEST_RUN"] = "1"

pytest_plugins = [
    "localstack.testing.pytest.cloudtrail_tracking",
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


@pytest.fixture(scope="session")
def aws_session() -> boto3.Session:
    """
    This fixture returns the Boto Session instance for testing.
    """
    return base_aws_session()


@pytest.fixture(scope="session")
def aws_client_factory(aws_session):
    """
    This fixture returns a client factory for testing.

    Use this fixture if you need to use custom endpoint or Boto config.
    """
    return base_aws_client_factory(aws_session)


@pytest.fixture(scope="session")
def aws_client(aws_client_factory):
    """
    This fixture can be used to obtain Boto clients for testing.

    The clients are configured with the primary testing credentials.
    """
    return primary_testing_aws_client(aws_client_factory)


@pytest.fixture(scope="session")
def secondary_aws_client(aws_client_factory):
    """
    This fixture can be used to obtain Boto clients for testing.

    The clients are configured with the secondary testing credentials.
    """
    return secondary_testing_aws_client(aws_client_factory)
