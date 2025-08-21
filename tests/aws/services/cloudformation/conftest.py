import re
from collections import Counter
from collections.abc import Iterable
from typing import TypeVar

import pytest

from localstack.services.cloudformation.v2.utils import is_v2_engine
from localstack.testing.aws.util import is_aws_cloud
from localstack.utils.collections import optional_list

SKIP_TYPE_RE = re.compile(r"^CFNV2\((?P<reason>[^\)]+)\)")


def skip_if_v1_provider(reason: str):
    return pytest.mark.skipif(
        condition=not is_v2_engine() and not is_aws_cloud(), reason=f"CFNV1: {reason}"
    )


_T = TypeVar("_T")


def skipped_v2_items(*items: Iterable[_T]) -> list[_T]:
    return optional_list(is_v2_engine(), items)


def pytest_report_collectionfinish(config, start_path, startdir, items):
    if not is_v2_engine():
        return

    v1_items, v2_skip_types = [], []
    for item in items:
        if skip := item.get_closest_marker("skipif"):
            if reason := skip.kwargs.get("reason"):
                if "CFNV2" in reason:
                    if match := SKIP_TYPE_RE.match(reason):
                        v2_skip_types.append(match.group("reason"))
                    else:
                        v2_skip_types.append("Other")
                elif "CFNV1" in reason:
                    v1_items.append(item.nodeid)
    header = f"CFNV2: skipped {len(v1_items)} v1 skips and {len(v2_skip_types)} v2 skips"
    types_count_parts = []
    for skip_type, count in sorted(
        Counter(v2_skip_types).items(), key=lambda e: e[1], reverse=True
    ):
        types_count_parts.append("- " + ": ".join([f"CFNV2({skip_type})", str(count)]))
    return [header] + types_count_parts
