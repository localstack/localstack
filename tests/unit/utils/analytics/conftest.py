import pytest

from localstack import config
from localstack.utils.analytics.metrics import Counter, get_metric_registry


@pytest.fixture(autouse=True)
def enable_analytics(monkeypatch):
    """Makes sure that all tests in this package are executed with analytics enabled."""
    monkeypatch.setattr(target=config, name="DISABLE_EVENTS", value=False)


@pytest.fixture(autouse=False)
def disable_analytics(monkeypatch):
    """Makes sure that all tests in this package are executed with analytics enabled."""
    monkeypatch.setattr(target=config, name="DISABLE_EVENTS", value=True)


@pytest.fixture(scope="function", autouse=True)
def reset_metric_registry() -> None:
    """Ensures each test starts with a fresh MetricRegistry."""
    registry = get_metric_registry()
    registry._registry.clear()  # Reset all registered metrics before each test


@pytest.fixture
def counter() -> Counter:
    return Counter(name="test_counter")


@pytest.fixture
def labeled_counter() -> Counter:
    return Counter(name="test_labeled_counter", labels=["status"])
