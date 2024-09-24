"""
Custom pytest mark typings
"""

import os
from typing import TYPE_CHECKING, Callable, List, Optional

import pytest
from _pytest.config import PytestPluginManager
from _pytest.config.argparsing import Parser


class AwsCompatibilityMarkers:
    # test has been successfully run against AWS, ideally multiple times
    validated = pytest.mark.aws_validated

    # implies aws_validated. test needs additional setup, configuration or some other steps not included in the test setup itself
    manual_setup_required = pytest.mark.aws_manual_setup_required

    # fails against AWS but should be made runnable against AWS in the future, basically a TODO
    needs_fixing = pytest.mark.aws_needs_fixing

    # only runnable against localstack by design
    only_localstack = pytest.mark.aws_only_localstack

    # it's unknown if the test works (reliably) against AWS or not
    unknown = pytest.mark.aws_unknown


class ParityMarkers:
    aws_validated = pytest.mark.aws_validated
    only_localstack = pytest.mark.only_localstack


class SkipSnapshotVerifyMarker:
    def __call__(
        self,
        *,
        paths: "Optional[List[str]]" = None,
        condition: "Optional[Callable[[...], bool]]" = None,
    ): ...


class MultiRuntimeMarker:
    def __call__(self, *, scenario: str, runtimes: Optional[List[str]] = None): ...


class SnapshotMarkers:
    skip_snapshot_verify: SkipSnapshotVerifyMarker = pytest.mark.skip_snapshot_verify


class Markers:
    aws = AwsCompatibilityMarkers
    parity = ParityMarkers  # TODO: in here for compatibility sake. Remove when -ext has been refactored to use @markers.aws.*
    snapshot = SnapshotMarkers

    multiruntime: MultiRuntimeMarker = pytest.mark.multiruntime

    # test selection
    acceptance_test = pytest.mark.acceptance_test
    skip_offline = pytest.mark.skip_offline
    only_on_amd64 = pytest.mark.only_on_amd64
    only_on_arm64 = pytest.mark.only_on_arm64
    resource_heavy = pytest.mark.resource_heavy
    only_in_docker = pytest.mark.only_in_docker
    # Tests to execute when updating snapshots for a new Lambda runtime
    lambda_runtime_update = pytest.mark.lambda_runtime_update


# pytest plugin
if TYPE_CHECKING:
    from _pytest.config import Config


@pytest.hookimpl
def pytest_addoption(parser: Parser, pluginmanager: PytestPluginManager):
    parser.addoption(
        "--offline",
        action="store_true",
        default=False,
        help="test run will not have an internet connection",
    )


def enforce_single_aws_marker(items: List[pytest.Item]):
    """Enforce that each test has exactly one aws compatibility marker"""
    marker_errors = []

    for item in items:
        # we should only concern ourselves with tests in tests/aws/
        if "tests/aws" not in item.fspath.dirname:
            continue

        aws_markers = list()
        for mark in item.iter_markers():
            if mark.name.startswith("aws_"):
                aws_markers.append(mark.name)

        if len(aws_markers) > 1:
            marker_errors.append(f"{item.nodeid}: Too many aws markers specified: {aws_markers}")
        elif len(aws_markers) == 0:
            marker_errors.append(
                f"{item.nodeid}: Missing aws marker. Specify at least one marker, e.g. @markers.aws.validated"
            )

    if marker_errors:
        raise pytest.UsageError(*marker_errors)


def filter_by_markers(config: "Config", items: List[pytest.Item]):
    """Filter tests by markers."""
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


@pytest.hookimpl
def pytest_collection_modifyitems(
    session: pytest.Session, config: "Config", items: List[pytest.Item]
) -> None:
    enforce_single_aws_marker(items)
    filter_by_markers(config, items)


@pytest.hookimpl
def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "skip_offline: mark the test to be skipped when the tests are run offline "
        "(this test explicitly / semantically needs an internet connection)",
    )
    config.addinivalue_line(
        "markers",
        "only_on_amd64: mark the test as running only in an amd64 (i.e., x86_64) environment",
    )
    config.addinivalue_line(
        "markers",
        "only_on_arm64: mark the test as running only in an arm64 environment",
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
