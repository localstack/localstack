import os

import pytest

os.environ["LOCALSTACK_INTERNAL_TEST_RUN"] = "1"

pytest_plugins = [
    "tests.integration.fixtures",
]


def pytest_addoption(parser):
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
