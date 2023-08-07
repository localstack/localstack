"""
Custom pytest mark typings
"""
from typing import Callable, Optional

import pytest


class AwsCompatibilityMarkers:
    validated = pytest.mark.aws_validated
    manual_setup_required = pytest.mark.aws__manual_setup_required  # implies aws_validated
    needs_fixing = pytest.mark.aws__needs_fixing
    only_localstack = pytest.mark.aws__only_localstack
    unknown = pytest.mark.aws__unknown


class ParityMarkers:
    aws_validated = pytest.mark.aws_validated
    manual_setup_required = pytest.mark.manual_setup_required  # implies aws_validated
    should_be_aws_validated = pytest.mark.should_be_aws_validated
    only_localstack = pytest.mark.only_localstack


class SkipSnapshotVerifyMarker:
    def __call__(
        self,
        *,
        paths: "Optional[list[str]]" = None,
        condition: "Optional[Callable[[...], bool]]" = None
    ):
        ...


class MultiRuntimeMarker:
    def __call__(self, *, scenario: str, runtimes: Optional[list[str]] = None):
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
