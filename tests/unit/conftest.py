import pytest

from localstack.testing.config import (
    TEST_AWS_ACCESS_KEY_ID,
    TEST_AWS_REGION_NAME,
    TEST_AWS_SECRET_ACCESS_KEY,
)


@pytest.fixture(autouse=True)
def set_boto_test_credentials_and_region(monkeypatch):
    """
    Automatically sets the default credentials and region for all unit tests.
    """
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", TEST_AWS_ACCESS_KEY_ID)
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", TEST_AWS_SECRET_ACCESS_KEY)
    monkeypatch.setenv("AWS_DEFAULT_REGION", TEST_AWS_REGION_NAME)
