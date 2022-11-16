import logging
from typing import Optional

from localstack import config
from localstack.services.infra import log_startup_message
from localstack.services.kinesis import kinesis_mock_server
from localstack.utils.aws import aws_stack
from localstack.utils.serving import Server

LOG = logging.getLogger(__name__)
_server: Optional[Server] = None  # server singleton


def start_kinesis(
    port=None, update_listener=None, asynchronous=None, persist_path: Optional[str] = None
) -> Server:
    """
    Creates a singleton of a Kinesis server and starts it on a new thread. Uses either Kinesis Mock or Kinesalite
    based on value of config.KINESIS_PROVIDER

    :param persist_path: path to persist data to
    :param port: port to run server on. Selects an arbitrary available port if None.
    :param update_listener: an update listener instance for server proxy
    :param asynchronous: currently unused but required by localstack.services.plugins.Service.start().
    TODO: either make use of this param or refactor Service.start() to not pass it.
    :returns: A running Kinesis server instance
    """
    global _server
    if not _server:
        _server = kinesis_mock_server.create_kinesis_mock_server(persist_path=persist_path)

    _server.start()
    log_startup_message("Kinesis")
    port = port or config.service_port("kinesis")

    return _server


def check_kinesis(expect_shutdown=False, print_error=False):
    out = None
    if not expect_shutdown:
        assert _server

    try:
        _server.wait_is_up()
        out = aws_stack.connect_to_service(
            service_name="kinesis", endpoint_url=_server.url
        ).list_streams()
    except Exception:
        if print_error:
            LOG.exception("Kinesis health check failed")
    if expect_shutdown:
        assert out is None
    else:
        assert out is not None and isinstance(out.get("StreamNames"), list)


def is_kinesis_running() -> bool:
    """
    Checks if there is a currently running Kinesis server instance.
    Currently, used by localstack_ext/utils/cloud_pods.py
    :returns: True is there is a running Kinesis server instance, False otherwise
    """
    global _server
    if _server is None:
        return False
    return _server.is_running()


def get_server():
    return _server
