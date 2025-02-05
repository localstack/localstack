import pytest

from localstack import config
from localstack.runtime.current import set_current_runtime


@pytest.fixture(autouse=True)
def enable_analytics(monkeypatch):
    """Makes sure that all tests in this package are executed with analytics enabled."""
    monkeypatch.setattr(config, "DISABLE_EVENTS", False)

class MockComponents:
    name = "mock-product"

class MockRuntime:
    components = MockComponents()

@pytest.fixture(autouse=True)
def mock_runtime():
    runtime = MockRuntime()
    set_current_runtime(runtime)
    yield
    set_current_runtime(None)
