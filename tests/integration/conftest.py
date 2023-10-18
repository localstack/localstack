from _pytest.config import Config

from localstack import config as localstack_config
from localstack import constants


def pytest_configure(config: Config):
    # FIXME: note that this should be the same as in tests/aws/conftest.py since both are currently run in
    #  the same CI test step, but only one localstack instance is started for both.
    config.option.start_localstack = True
    localstack_config.FORCE_SHUTDOWN = False
    localstack_config.GATEWAY_LISTEN = localstack_config.UniqueHostAndPortList(
        [localstack_config.HostAndPort(host="0.0.0.0", port=constants.DEFAULT_PORT_EDGE)]
    )
