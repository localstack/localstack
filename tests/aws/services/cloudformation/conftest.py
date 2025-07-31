from functools import partial

import pytest

from localstack.services.cloudformation.v2.utils import is_v2_engine
from localstack.testing.aws.util import is_aws_cloud


def skip_if_v2_provider(reason: str):
    return pytest.mark.skipif(condition=is_v2_engine() and not is_aws_cloud(), reason=reason)


def skip_if_v1_provider(*, reason: str):
    return pytest.mark.skipif(condition=not is_v2_engine() and not is_aws_cloud(), reason=reason)


def optional_snapshot_skips(*skips: str, condition: bool) -> list[str]:
    if condition:
        return list(skips)
    else:
        return []


extra_v2_snapshot_skips = partial(optional_snapshot_skips, condition=is_v2_engine())
