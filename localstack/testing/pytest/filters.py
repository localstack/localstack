import os
from typing import List

import pytest
from _pytest.config import Config, PytestPluginManager
from _pytest.config.argparsing import Parser
from _pytest.main import Session
from _pytest.nodes import Item


@pytest.hookimpl
def pytest_addoption(parser: Parser, pluginmanager: PytestPluginManager):
    parser.addoption("--filter-fixtures", action="store")


@pytest.hookimpl
def pytest_collection_modifyitems(session: Session, config: Config, items: List[Item]):
    ff = config.getoption("--filter-fixtures")
    if ff:
        # TODO: add more sophisticated combinations (=> like pytest -m and -k)
        #   currently this is implemented in a way that any overlap between the fixture names will lead to selection
        filter_fixtures = set(ff.split(","))
        selected = []
        deselected = []
        for item in items:
            if hasattr(item, "fixturenames") and filter_fixtures.isdisjoint(set(item.fixturenames)):
                deselected.append(item)
            else:
                selected.append(item)
        items[:] = selected
        config.hook.pytest_deselected(items=deselected)


def filter_tests(config, items):
    """Filter tests by markers.
    Re-usable helper for `pytest_collection_modifyitems`."""
    from localstack import config as localstack_config
    from localstack.utils.bootstrap import in_ci
    from localstack.utils.platform import Arch, get_arch

    is_offline = config.getoption("--offline")
    is_in_docker = localstack_config.is_in_docker
    is_in_ci = in_ci()
    is_amd64 = get_arch() == Arch.amd64
    is_arm64 = get_arch() == Arch.arm64
    # Inlining `is_aws_cloud()` here because localstack.testing.aws.util imports boto3,
    # which is not installed for the CLI tests
    is_real_aws = os.environ.get("TEST_TARGET", "") == "AWS_CLOUD"

    if is_real_aws:
        # Do not skip any tests if they are executed against real AWS
        return

    skip_offline = pytest.mark.skip(
        reason="Test cannot be executed offline / in a restricted network environment. "
        "Add network connectivity and remove the --offline option when running "
        "the test."
    )
    only_in_docker = pytest.mark.skip(
        reason="Test requires execution inside Docker (e.g., to install system packages)"
    )
    only_on_amd64 = pytest.mark.skip(
        reason="Test uses features that are currently only supported for AMD64. Skipping in CI."
    )
    only_on_arm64 = pytest.mark.skip(
        reason="Test uses features that are currently only supported for ARM64. Skipping in CI."
    )

    for item in items:
        if is_offline and "skip_offline" in item.keywords:
            item.add_marker(skip_offline)
        if not is_in_docker and "only_in_docker" in item.keywords:
            item.add_marker(only_in_docker)
        if is_in_ci and not is_amd64 and "only_on_amd64" in item.keywords:
            item.add_marker(only_on_amd64)
        if is_in_ci and not is_arm64 and "only_on_arm64" in item.keywords:
            item.add_marker(only_on_arm64)
