import logging

from localstack import config
from localstack.services.infra import start_moto_server

LOG = logging.getLogger(__name__)


def start_swf(port=None, backend_port=None, asynchronous=None, update_listener=None):
    port = port or config.service_port("swf")

    return start_moto_server(
        key="swf",
        name="SWF",
        asynchronous=asynchronous,
        port=port,
        update_listener=update_listener,
    )
