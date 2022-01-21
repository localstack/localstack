import logging
from typing import Optional

from localstack import config
from localstack.services.kinesis import kinesis_mock_server, kinesalite_server, kinesis_listener
from localstack.services.infra import log_startup_message, start_proxy_for_service
from localstack.utils.aws import aws_stack
from localstack.utils.serving import Server

LOG = logging.getLogger(__name__)
_server: Optional[Server] = None  # server singleton


def start_kinesis(port=None, update_listener=None, asynchronous=None):
    global _server
    if not _server:
        if config.KINESIS_PROVIDER == "kinesis-mock":
            _server = kinesis_mock_server.create_kinesis_mock_server()
        elif config.KINESIS_PROVIDER == "kinesalite":
            _server = kinesalite_server.create_kinesalite_server()
        else:
            raise Exception('Unsupported Kinesis provider "%s"' % config.KINESIS_PROVIDER)
    _start_kinesis_helper(_server, port=port, update_listener=update_listener)
    return _server


def _start_kinesis_helper(server: Server, port=None, update_listener=None) -> Server:
    server.start()
    log_startup_message("Kinesis")
    port = port or config.PORT_KINESIS
    start_proxy_for_service(
        "kinesis",
        port,
        backend_port=_server.port,
        update_listener=update_listener,
    )


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


def restart_kinesis():
    global _server
    if _server:
        _server.shutdown()
        _server.join(timeout=10)
        _server = None

    LOG.debug("Restarting Kinesis process ...")
    start_kinesis(update_listener=kinesis_listener)
