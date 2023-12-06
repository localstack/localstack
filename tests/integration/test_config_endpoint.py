import pytest
import requests

from localstack import config
from localstack.http import Resource
from localstack.services.internal import ConfigResource, get_internal_apis
from localstack.utils import config_listener


@pytest.fixture
def config_endpoint(monkeypatch):
    if config.ENABLE_CONFIG_UPDATES:
        return

    router = get_internal_apis()
    monkeypatch.setattr(config, "ENABLE_CONFIG_UPDATES", True)
    # will listen on /_localstack/config
    rules = router.add(Resource("/_localstack/config", ConfigResource()))
    yield
    router.remove(rules)


def test_config_endpoint(config_endpoint):
    key = value = None

    def custom_listener(config_key, config_value):
        nonlocal key, value
        key = config_key
        value = config_value

    config.FOO = None
    config_listener.CONFIG_LISTENERS.append(custom_listener)

    # test the Route
    body = {"variable": "FOO", "value": "BAZ"}
    # test the ProxyListener
    url = f"{config.internal_service_url()}/_localstack/config"
    response = requests.post(url, json=body)
    assert response.ok
    response_body = response.json()
    assert body == response_body
    assert body["value"] == config.FOO
    assert body["variable"] == key
    assert body["value"] == value

    # test numeric value update
    body = {"variable": "FOO", "value": 0.9}
    response = requests.post(url, json=body)
    assert response.ok
    assert config.FOO == 0.9
    assert isinstance(config.FOO, float)

    del config.FOO
    config_listener.CONFIG_LISTENERS.remove(custom_listener)
