import logging

from localstack import config
from localstack.services.infra import start_moto_server
from localstack.services.s3control import s3control_listener
from localstack.utils.aws import aws_stack
from localstack.utils.common import wait_for_port_open

LOGGER = logging.getLogger(__name__)


def start_s3control(port=None, backend_port=None, asynchronous=None, update_listener=None):
    port = port or config.service_port("s3control")
    return start_moto_server(
        key="s3control",
        name="s3control",
        port=port,
        backend_port=backend_port,
        asynchronous=asynchronous,
        update_listener=update_listener,
    )
