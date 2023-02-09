import json
import logging
import re
from typing import Callable, List

from requests.models import Response

from localstack import config, constants
from localstack.deprecations import deprecated_endpoint
from localstack.services.generic_proxy import ProxyListener

LOG = logging.getLogger(__name__)

CONFIG_LISTENERS: List[Callable[[str, str], None]] = []


def trigger_config_listeners(variable, new_value):
    LOG.debug("Updating config listeners")
    for listener in CONFIG_LISTENERS:
        listener(variable, new_value)


def update_config_variable(variable, new_value):
    if new_value is not None:
        LOG.info('Updating value of config variable "%s": %s', variable, new_value)
        setattr(config, variable, new_value)
        trigger_config_listeners(variable, new_value)


def _update_config_variable_handler(data):
    response = Response()
    data = json.loads(data)
    variable = data.get("variable", "")
    response._content = "{}"
    response.status_code = 200
    if not re.match(r"^[_a-zA-Z0-9]+$", variable):
        response.status_code = 400
        return response
    new_value = data.get("value")
    update_config_variable(variable, new_value)
    value = getattr(config, variable, None)
    result = {"variable": variable, "value": value}
    response._content = json.dumps(result)
    return response


class ConfigUpdateProxyListener(ProxyListener):
    """Default proxy listener that intercepts requests to retrieve or update config variables."""

    def __init__(self):
        self._handler = deprecated_endpoint(
            endpoint=_update_config_variable_handler,
            previous_path=constants.CONFIG_UPDATE_PATH,
            deprecation_version="1.4.0",
            new_path="/_localstack/config",
        )

    def forward_request(self, method, path, data, headers):
        if path != constants.CONFIG_UPDATE_PATH or method != "POST":
            return True

        return self._handler(data)


CONFIG_UPDATE_LISTENER = ConfigUpdateProxyListener()


def start_listener():
    if config.ENABLE_CONFIG_UPDATES:
        ProxyListener.DEFAULT_LISTENERS.append(CONFIG_UPDATE_LISTENER)


def remove_listener():
    if not config.ENABLE_CONFIG_UPDATES:
        try:
            ProxyListener.DEFAULT_LISTENERS.remove(CONFIG_UPDATE_LISTENER)
        except ValueError:
            pass
