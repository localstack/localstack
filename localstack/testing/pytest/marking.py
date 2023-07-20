"""
Custom pytest mark typings
"""
from typing import Callable, Optional

import pytest


class ParityMarkers:
    aws_validated = pytest.mark.aws_validated
    only_localstack = pytest.mark.aws_validated


class SkipSnapshotVerifyMarker:
    def __call__(
        self,
        *,
        paths: Optional[list[str]] = None,
        condition: Optional[Callable[[...], bool]] = None
    ):
        ...


class SnapshotMarkers:
    skip_snapshot_verify: SkipSnapshotVerifyMarker = pytest.mark.skip_snapshot_verify


class Markers:
    parity = ParityMarkers
    snapshot = SnapshotMarkers

    skip_offline = pytest.mark.skip_offline
    only_on_amd64 = pytest.mark.only_on_amd64
