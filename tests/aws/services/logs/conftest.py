import pytest

from localstack import config
from localstack.testing.aws.util import is_aws_cloud


def is_legacy_provider() -> bool:
    return config.SERVICE_PROVIDER_CONFIG.get_provider("logs") != "v2"


def is_v2_provider() -> bool:
    return config.SERVICE_PROVIDER_CONFIG.get_provider("logs") == "v2"


def skip_if_legacy_engine(reason: str | None = None):
    return pytest.mark.skipif(
        condition=not is_v2_provider() and not is_aws_cloud(),
        reason=reason or "Not implemented in legacy engine",
    )
