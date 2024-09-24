import pytest

from localstack import config


@pytest.fixture(autouse=True)
def enable_analytics(monkeypatch):
    """Makes sure that all tests in this package are executed with analytics enabled."""
    monkeypatch.setattr(config, "DISABLE_EVENTS", False)
