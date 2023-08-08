"""
Custom pytest mark typings
"""
from typing import Callable, List, Optional

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
        condition: "Optional[Callable[[...], bool]]" = None
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
    skip_offline = pytest.mark.skip_offline
    only_on_amd64 = pytest.mark.only_on_amd64
    resource_heavy = pytest.mark.resource_heavy
    only_in_docker = pytest.mark.only_in_docker
