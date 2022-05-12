import os

import pytest

only_localstack = pytest.mark.skipif(
    os.environ.get("TEST_TARGET") == "AWS_CLOUD",
    reason="test only applicable if run against localstack",
)
