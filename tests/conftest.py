import os
from typing import TYPE_CHECKING

import pytest
from _pytest.config import PytestPluginManager
from _pytest.config.argparsing import Parser
from localstack_snapshot.snapshots.transformer import RegexTransformer

from localstack.constants import TEST_AWS_REGION_NAME
from localstack.testing.aws.util import is_aws_cloud
from localstack.testing.snapshots.transformer_utility import (
    SNAPSHOT_BASIC_TRANSFORMER,
    SNAPSHOT_BASIC_TRANSFORMER_NEW,
    TransformerUtility,
)
from localstack.utils.bootstrap import is_api_enabled

if TYPE_CHECKING:
    from localstack_snapshot.snapshots import SnapshotSession

os.environ["LOCALSTACK_INTERNAL_TEST_RUN"] = "1"

pytest_plugins = [
    "localstack.testing.pytest.cloudtrail_tracking",
    "localstack.testing.pytest.fixtures",
    "localstack.testing.pytest.container",
    "localstack_snapshot.pytest.snapshot",
    "localstack.testing.pytest.filters",
    "localstack.testing.pytest.fixture_conflicts",
    "localstack.testing.pytest.detect_thread_leakage",
    "localstack.testing.pytest.marking",
    "localstack.testing.pytest.marker_report",
    "localstack.testing.pytest.in_memory_localstack",
    "localstack.testing.pytest.validation_tracking",
]


# FIXME: remove this, quick hack to prevent the HTTPServer fixture to spawn non-daemon threads
def pytest_sessionstart(session):
    import threading

    try:
        from pytest_httpserver import HTTPServer, HTTPServerError
        from werkzeug.serving import make_server

        from localstack.utils.patch import Patch

        def start_non_daemon_thread(self):
            if self.is_running():
                raise HTTPServerError("Server is already running")

            self.server = make_server(
                self.host, self.port, self.application, ssl_context=self.ssl_context
            )
            self.port = self.server.port  # Update port (needed if `port` was set to 0)
            self.server_thread = threading.Thread(target=self.thread_target, daemon=True)
            self.server_thread.start()

        patch = Patch(name="start", obj=HTTPServer, new=start_non_daemon_thread)
        patch.apply()

    except ImportError:
        # this will be executed in the CLI tests as well, where we don't have the pytest_httpserver dependency
        # skip in that case
        pass


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
def snapshot(request, _snapshot_session: "SnapshotSession", aws_client):
    account_id = aws_client.sts.get_caller_identity()["Account"]
    region = aws_client.sts.meta.region_name

    # Overwrite utility with our own => Will be refactored in the future
    _snapshot_session.transform = TransformerUtility

    _snapshot_session.add_transformer(RegexTransformer(account_id, "1" * 12), priority=2)
    _snapshot_session.add_transformer(RegexTransformer(region, "<region>"), priority=2)

    # TODO: temporary to migrate to new default transformers.
    #   remove this after all exemptions are gone
    exemptions = [
        "tests/aws/services/acm",
        "tests/aws/services/apigateway",
        "tests/aws/services/cloudwatch",
        "tests/aws/services/cloudformation",
        "tests/aws/services/dynamodb",
        "tests/aws/services/events",
        "tests/aws/services/iam",
        "tests/aws/services/kinesis",
        "tests/aws/services/kms",
        "tests/aws/services/lambda_",
        "tests/aws/services/logs",
        "tests/aws/services/route53",
        "tests/aws/services/route53resolver",
        "tests/aws/services/s3",
        "tests/aws/services/secretsmanager",
        "tests/aws/services/ses",
        "tests/aws/services/sns",
        "tests/aws/services/stepfunctions",
        "tests/aws/services/sqs",
        "tests/aws/services/transcribe",
        "tests/aws/scenario/bookstore",
        "tests/aws/scenario/note_taking",
        "tests/aws/scenario/lambda_destination",
        "tests/aws/scenario/loan_broker",
    ]
    if any([e in request.fspath.dirname for e in exemptions]):
        _snapshot_session.add_transformer(SNAPSHOT_BASIC_TRANSFORMER, priority=2)
    else:
        _snapshot_session.add_transformer(SNAPSHOT_BASIC_TRANSFORMER_NEW, priority=2)

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


@pytest.fixture(name="region", scope="session")
def fixture_region(aws_client):
    if is_aws_cloud() or is_api_enabled("sts"):
        return aws_client.sts.meta.region_name
    else:
        return TEST_AWS_REGION_NAME
