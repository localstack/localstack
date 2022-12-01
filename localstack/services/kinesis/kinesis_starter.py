import logging
from typing import Dict, Optional

from localstack import config
from localstack.aws.accounts import get_aws_account_id
from localstack.constants import DEFAULT_AWS_ACCOUNT_ID
from localstack.services.infra import log_startup_message
from localstack.services.kinesis import kinesis_mock_server
from localstack.utils.aws import aws_stack
from localstack.utils.serving import Server

LOG = logging.getLogger(__name__)

_server: Dict[str, Server] = {}  # server singleton keyed by account IDs


def start_kinesis(
    port=None,
    update_listener=None,
    asynchronous=None,
    persist_path: Optional[str] = None,
    account_id=None,
) -> Server:
    """
    Creates a singleton of a Kinesis server and starts it on a new thread. Uses Kinesis Mock

    :param persist_path: path to persist data to
    :param port: port to run server on. Selects an arbitrary available port if None.
    :param update_listener: an update listener instance for server proxy
    :param asynchronous: currently unused but required by localstack.services.plugins.Service.start().
    TODO: either make use of this param or refactor Service.start() to not pass it.
    :param account_id: account ID to use for this instance of Kinesis-Mock
    :returns: A running Kinesis server instance
    """
    global _server

    if account_id is None:
        account_id = get_aws_account_id()

    if account_id not in _server:
        # To support multi-accounts we use separate instance of Kinesis-Mock per account
        # See https://github.com/etspaceman/kinesis-mock/issues/377
        if not _server.get(account_id):
            _server[account_id] = kinesis_mock_server.create_kinesis_mock_server(
                account_id=account_id, persist_path=persist_path
            )

        _server[account_id].start()
        log_startup_message("Kinesis")
        port = port or config.service_port("kinesis")

        check_kinesis(account_id=account_id)

    return _server[account_id]


def check_kinesis(
    expect_shutdown=False, print_error=False, account_id: str = DEFAULT_AWS_ACCOUNT_ID
):
    out = None
    if not expect_shutdown:
        assert _server.get(account_id)

    try:
        _server[account_id].wait_is_up()
        out = aws_stack.connect_to_service(
            service_name="kinesis", endpoint_url=_server[account_id].url
        ).list_streams()
    except Exception:
        if print_error:
            LOG.exception("Kinesis health check failed")
    if expect_shutdown:
        assert out is None
    else:
        assert out is not None and isinstance(out.get("StreamNames"), list)


def get_server(account_id: str) -> Server:
    return _server[account_id]
