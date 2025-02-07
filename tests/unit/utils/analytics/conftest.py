import pytest

from localstack import config
from localstack.runtime.current import get_current_runtime, set_current_runtime


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
    try:
        # don't do anything if a runtime is set
        get_current_runtime()
        yield
    except ValueError:
        # set a mock runtime if no runtime is set
        set_current_runtime(MockRuntime())
        yield
        set_current_runtime(None)
