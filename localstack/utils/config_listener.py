import json
import logging
import re
from typing import Callable, List

from requests.models import Response

from localstack import config, constants
from localstack.services.generic_proxy import ProxyListener

LOG = logging.getLogger(__name__)

CONFIG_LISTENERS: List[Callable[[str, str], None]] = []


def trigger_config_listeners(variable, new_value):
    LOG.debug("Updating config listeners")
    for listener in CONFIG_LISTENERS:
        listener(variable, new_value)


def update_config_variable(variable, new_value):
    if new_value is not None:
        LOG.info('Updating value of config variable "%s": %s' % (variable, new_value))
        setattr(config, variable, new_value)
        trigger_config_listeners(variable, new_value)


class ConfigUpdateProxyListener(ProxyListener):
    """Default proxy listener that intercepts requests to retrieve or update config variables."""

    def forward_request(self, method, path, data, headers):
        if path != constants.CONFIG_UPDATE_PATH or method != "POST":
            return True
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


def start_listener():
    if config.ENABLE_CONFIG_UPDATES:
        ProxyListener.DEFAULT_LISTENERS.append(ConfigUpdateProxyListener())
