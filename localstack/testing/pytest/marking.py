"""
Custom pytest mark typings
"""
from typing import TYPE_CHECKING, Callable, List, Optional

import pytest


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
    ):
        ...


class MultiRuntimeMarker:
    def __call__(self, *, scenario: str, runtimes: Optional[List[str]] = None):
        ...


class SnapshotMarkers:
    skip_snapshot_verify: SkipSnapshotVerifyMarker = pytest.mark.skip_snapshot_verify


class Markers:
    aws = AwsCompatibilityMarkers
    parity = ParityMarkers  # TODO: in here for compatibility sake. Remove when -ext has been refactored to use @markers.aws.*
    snapshot = SnapshotMarkers

    multiruntime: MultiRuntimeMarker = pytest.mark.multiruntime

    # test selection
    acceptance_test_beta = (
        pytest.mark.acceptance_test
    )  # for now with a _beta suffix to make clear they are not really used as acceptance tests yet
    skip_offline = pytest.mark.skip_offline
    only_on_amd64 = pytest.mark.only_on_amd64
    resource_heavy = pytest.mark.resource_heavy
    only_in_docker = pytest.mark.only_in_docker


# pytest plugin
if TYPE_CHECKING:
    from _pytest.config import Config


@pytest.hookimpl
def pytest_collection_modifyitems(
    session: pytest.Session, config: "Config", items: List[pytest.Item]
) -> None:
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
