from collections.abc import Iterable
from typing import TypeVar

import pytest

from localstack.services.cloudformation.v2.utils import is_v2_engine
from localstack.testing.aws.util import is_aws_cloud
from localstack.utils.collections import optional_list


def skip_if_v2_provider(*types: str, reason: str = ""):
    if reason:
        reason = f"CFNV2({','.join(types)}): {reason}"
    else:
        reason = f"CFNV2({','.join(types)})"
    return pytest.mark.skipif(condition=is_v2_engine() and not is_aws_cloud(), reason=reason)


def skip_if_v1_provider(reason: str):
    return pytest.mark.skipif(
        condition=not is_v2_engine() and not is_aws_cloud(), reason=f"CFNV1: {reason}"
    )


_T = TypeVar("_T")


def skipped_v2_items(*items: Iterable[_T]) -> list[_T]:
    return optional_list(is_v2_engine(), items)


def pytest_report_collectionfinish(config, start_path, startdir, items):
    v1_items, v2_items = [], []
    for item in items:
        if skip := item.get_closest_marker("skipif"):
            if "CFNV2" in skip.kwargs.get("reason"):
                v2_items.append(item.nodeid)
            elif "CFNV1" in skip.kwargs.get("reason"):
                v1_items.append(item.nodeid)
    return f"CFNV2: skipped {len(v1_items)} v1 skips and {len(v2_items)} v2 skips"
