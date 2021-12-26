import pytest
import requests

from localstack import config
from localstack.utils import config_listener


@pytest.fixture
def config_endpoint():
    cur_value = config.ENABLE_CONFIG_UPDATES
    config.ENABLE_CONFIG_UPDATES = True
    config_listener.start_listener()
    yield
    config.ENABLE_CONFIG_UPDATES = cur_value
    config_listener.remove_listener()


def test_config_endpoint(config_endpoint):
    key = value = None

    def custom_listener(config_key, config_value):
        nonlocal key, value
        key = config_key
        value = config_value

    config.FOO = None
    body = {"variable": "FOO", "value": "BAR"}
    config_listener.CONFIG_LISTENERS.append(custom_listener)
    url = f"{config.get_edge_url()}/?_config_"
    print(url)
    response = requests.post(url, json=body)
    assert 200 == response.status_code
    response_body = response.json()
    assert body == response_body
    assert body["value"] == config.FOO
    assert body["variable"] == key
    assert body["value"] == value
