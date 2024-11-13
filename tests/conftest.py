import os

import pytest

os.environ["LOCALSTACK_INTERNAL_TEST_RUN"] = "1"

pytest_plugins = [
    "localstack.testing.pytest.fixtures",
    "localstack.testing.pytest.container",
    "localstack_snapshot.pytest.snapshot",
    "localstack.testing.pytest.filters",
    "localstack.testing.pytest.fixture_conflicts",
    "localstack.testing.pytest.marking",
    "localstack.testing.pytest.marker_report",
    "localstack.testing.pytest.in_memory_localstack",
    "localstack.testing.pytest.validation_tracking",
    "localstack.testing.pytest.path_filter",
    "localstack.testing.pytest.stepfunctions.fixtures",
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


@pytest.fixture(scope="session")
def aws_session():
    """
    This fixture returns the Boto Session instance for testing.
    """
    from localstack.testing.aws.util import base_aws_session

    return base_aws_session()


@pytest.fixture(scope="session")
def secondary_aws_session():
    """
    This fixture returns the Boto Session instance for testing a secondary account.
    """
    from localstack.testing.aws.util import secondary_aws_session

    return secondary_aws_session()


@pytest.fixture(scope="session")
def aws_client_factory(aws_session):
    """
    This fixture returns a client factory for testing.

    Use this fixture if you need to use custom endpoint or Boto config.
    """
    from localstack.testing.aws.util import base_aws_client_factory

    return base_aws_client_factory(aws_session)


@pytest.fixture(scope="session")
def secondary_aws_client_factory(secondary_aws_session):
    """
    This fixture returns a client factory for testing a secondary account.

    Use this fixture if you need to use custom endpoint or Boto config.
    """
    from localstack.testing.aws.util import base_aws_client_factory

    return base_aws_client_factory(secondary_aws_session)


@pytest.fixture(scope="session")
def aws_client(aws_client_factory):
    """
    This fixture can be used to obtain Boto clients for testing.

    The clients are configured with the primary testing credentials.
    """
    from localstack.testing.aws.util import base_testing_aws_client

    return base_testing_aws_client(aws_client_factory)


@pytest.fixture(scope="session")
def secondary_aws_client(secondary_aws_client_factory):
    """
    This fixture can be used to obtain Boto clients for testing a secondary account.

    The clients are configured with the secondary testing credentials.
    The region is not overridden.
    """
    from localstack.testing.aws.util import base_testing_aws_client

    return base_testing_aws_client(secondary_aws_client_factory)
