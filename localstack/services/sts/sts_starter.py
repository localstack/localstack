from localstack.constants import DEFAULT_PORT_STS_BACKEND
from localstack.services.infra import start_moto_server
from localstack import config


def start_sts(port=None, asynchronous=False, update_listener=None):
    port = port or config.PORT_STS

    return start_moto_server('sts', port, name='STS', asynchronous=asynchronous,
                             backend_port=DEFAULT_PORT_STS_BACKEND, update_listener=update_listener)
