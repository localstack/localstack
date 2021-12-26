import logging
from typing import Optional

from localstack.services.dynamodb import dynamodb_listener
from localstack.services.dynamodb.server import DynamodbServer, create_dynamodb_server
from localstack.services.infra import log_startup_message, start_proxy_for_service
from localstack.utils.aws import aws_stack

LOG = logging.getLogger(__name__)

# server singleton
_server: Optional[DynamodbServer] = None


def check_dynamodb(expect_shutdown=False, print_error=False):
    out = None

    if not expect_shutdown:
        assert _server

    try:
        _server.wait_is_up()
        out = aws_stack.connect_to_service("dynamodb", endpoint_url=_server.url).list_tables()
    except Exception:
        if print_error:
            LOG.exception("DynamoDB health check failed")
    if expect_shutdown:
        assert out is None
    else:
        assert isinstance(out["TableNames"], list)


def start_dynamodb(port=None, asynchronous=True, update_listener=None):
    global _server
    if not _server:
        _server = create_dynamodb_server()

    _server.start()

    log_startup_message("DynamoDB")
    start_proxy_for_service(
        "dynamodb",
        port,
        backend_port=_server.port,
        update_listener=update_listener,
    )
    return _server


def restart_dynamodb():
    global _server
    if _server:
        _server.shutdown()
        _server.join(timeout=10)
        _server = None

    LOG.debug("Restarting DynamoDB process ...")
    start_dynamodb(asynchronous=True, update_listener=dynamodb_listener.UPDATE_DYNAMODB)
