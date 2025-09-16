import re
from collections.abc import Iterable
from typing import TypeVar

import pytest

from localstack.services.cloudformation.v2.utils import is_v2_engine
from localstack.testing.aws.util import is_aws_cloud
from localstack.utils.collections import optional_list

SKIP_TYPE_RE = re.compile(r"^CFNV2\((?P<reason>[^\)]+)\)")


def skip_if_legacy_engine(reason: str | None = None):
    return pytest.mark.skipif(
        condition=not is_v2_engine() and not is_aws_cloud(),
        reason=reason or "Not implemented in legacy engine",
    )


_T = TypeVar("_T")


def skipped_v2_items(*items: Iterable[_T]) -> list[_T]:
    return optional_list(is_v2_engine(), items)
