import logging
from typing import Optional

from localstack import config
from localstack.services.infra import log_startup_message, start_proxy_for_service
from localstack.services.kinesis import kinesalite_server, kinesis_listener, kinesis_mock_server
from localstack.utils.aws import aws_stack
from localstack.utils.serving import Server

LOG = logging.getLogger(__name__)
_server: Optional[Server] = None  # server singleton


def start_kinesis(port=None, update_listener=None, asynchronous=None) -> Server:
    """
    Creates a singleton of a Kinesis server and starts it on a new thread. Uses either Kinesis Mock or Kinesalite
    based on value of config.KINESIS_PROVIDER

    :param port: port to run server on. Selects an arbitrary available port if None.
    :param update_listener: an update listener instance for server proxy
    :param asynchronous: currently unused but required by localstack.services.plugins.Service.start().
    TODO: either make use of this param or refactor Service.start() to not pass it.
    :returns: A running Kinesis server instance
    :raises: ValueError: Value of config.KINESIS_PROVIDER is not recognized as one of "kinesis-mock" or "kinesalite"
    """
    global _server
    if not _server:
        if config.KINESIS_PROVIDER == "kinesis-mock":
            _server = kinesis_mock_server.create_kinesis_mock_server()
        elif config.KINESIS_PROVIDER == "kinesalite":
            _server = kinesalite_server.create_kinesalite_server()
        else:
            raise ValueError('Unsupported Kinesis provider "%s"' % config.KINESIS_PROVIDER)

    _server.start()
    log_startup_message("Kinesis")
    port = port or config.service_port("kinesis")
    start_proxy_for_service(
        "kinesis",
        port,
        backend_port=_server.port,
        update_listener=update_listener,
    )
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


def kinesis_running() -> bool:
    """
    Checks if there is a currently running Kinesis server instance.
    Currently used by localstack_ext/utils/cloud_pods.py
    :returns: True is there is a running Kinesis server instance, False otherwise
    TODO: rename this function to is_kinesis_running() for clarity
    """
    global _server
    if _server is None:
        return False
    return _server.is_running()


def restart_kinesis():
    global _server
    if _server:
        _server.shutdown()
        _server.join(timeout=10)
        _server = None

    LOG.debug("Restarting Kinesis process ...")
    start_kinesis(update_listener=kinesis_listener.UPDATE_KINESIS)
