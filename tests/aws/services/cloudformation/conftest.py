from typing import Iterable, TypeVar

import pytest

from localstack.services.cloudformation.v2.utils import is_v2_engine
from localstack.testing.aws.util import is_aws_cloud
from localstack.utils.collections import optional_list


def skip_if_v2_provider(reason: str):
    return pytest.mark.skipif(condition=is_v2_engine() and not is_aws_cloud(), reason=reason)


def skip_if_v1_provider(*, reason: str):
    return pytest.mark.skipif(condition=not is_v2_engine() and not is_aws_cloud(), reason=reason)


_T = TypeVar("_T")


def skipped_v2_items(*items: Iterable[_T]) -> list[_T]:
    return optional_list(is_v2_engine(), items)
