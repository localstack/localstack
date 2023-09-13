from _pytest.config import Config

from localstack import config as localstack_config
from localstack import constants


def pytest_configure(config: Config):
    # FIXME:
    config.option.start_localstack = True
    localstack_config.FORCE_SHUTDOWN = False
    localstack_config.GATEWAY_LISTEN = [
        localstack_config.HostAndPort(host="0.0.0.0", port=constants.DEFAULT_PORT_EDGE)
    ]
