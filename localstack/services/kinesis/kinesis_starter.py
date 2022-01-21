import logging
from typing import Optional

from localstack import config
from localstack.services.kinesis import kinesis_mock_server, kinesalite_server
from localstack.services.infra import log_startup_message, start_proxy_for_service
from localstack.utils.aws import aws_stack
from localstack.utils.serving import Server

LOG = logging.getLogger(__name__)
_server: Optional[Server] = None  # server singleton


def start_kinesis(port=None, asynchronous=False, update_listener=None):
    port = port or config.PORT_KINESIS
    if config.KINESIS_PROVIDER == "kinesis-mock":
        return start_kinesis_mock(port=port, update_listener=update_listener)
    if config.KINESIS_PROVIDER == "kinesalite":
        return start_kinesalite(
            port=port, update_listener=update_listener
        )
    raise Exception('Unsupported Kinesis provider "%s"' % config.KINESIS_PROVIDER)


def start_kinesis_mock(port=None, update_listener=None):
    global _server
    if not _server:
        # TODO rename create_mock_kinesis_server -> create_kinesis_mock_server
        _server = kinesis_mock_server.create_mock_kinesis_server()

    _server.start()
    log_startup_message("Kinesis")
    start_proxy_for_service(
        "kinesis",
        port, # TODO should this != backend_port?
        backend_port=_server.port,
        update_listener=update_listener,
    )
    return _server


# TODO DRY this out
def start_kinesalite(port=None, update_listener=None):
    global _server
    if not _server:
        _server = kinesalite_server.create_kinesalite_server()

    _server.start()
    log_startup_message("Kinesis")
    start_proxy_for_service(
        "kinesis",
        port, # TODO should this != backend_port?
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

# TODO make this like dynamodb restarter
def restart_kinesis():
    pass
    '''
    if PROCESS_THREAD:
        LOG.debug("Restarting Kinesis process ...")
        PROCESS_THREAD.stop()
        kinesis_stopped.wait()
        kinesis_stopped.clear()
        start_kinesis(asynchronous=True, update_listener=kinesis_listener.UPDATE_KINESIS)
        # giving the process some time to startup; TODO: to be replaced with service lifecycle plugin
        time.sleep(1)
    '''