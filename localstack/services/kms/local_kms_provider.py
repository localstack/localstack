import logging
import threading
from typing import Dict, Optional

from localstack.aws.accounts import get_aws_account_id
from localstack.aws.api.kms import KmsApi
from localstack.config import LOCALSTACK_HOSTNAME
from localstack.constants import DEFAULT_AWS_ACCOUNT_ID
from localstack.services.infra import log_startup_message
from localstack.services.kms import local_kms_server
from localstack.services.plugins import ServiceLifecycleHook
from localstack.utils.serving import Server
from localstack.utils.sync import SynchronizedDefaultDict

LOG = logging.getLogger(__name__)

_SERVERS: Dict[str, Server] = {}  # server singleton keyed by account IDs
_LOCKS = SynchronizedDefaultDict(threading.RLock)


class LocalKmsProvider(KmsApi, ServiceLifecycleHook):
    def start_and_get_backend(self):
        """
        Start the local-kms backend and return the URL of the server.
        """
        account_id = get_aws_account_id()
        start_kms_local(account_id=account_id)
        return f"http://{LOCALSTACK_HOSTNAME}:{get_server(account_id).port}"


def start_kms_local(
    port=None,
    asynchronous=None,
    update_listener=None,
    persist_path: Optional[str] = None,
    account_id=None,
):
    """
    Creates a singleton of a KMS server and starts it on a new thread. Uses local-kms

    :param persist_path: path to persist data to
    :param port: port to run server on. Selects an arbitrary available port if None.
    :param update_listener: an update listener instance for server proxy
    :param asynchronous: currently unused but required by localstack.services.plugins.Service.start().
    :param account_id: account ID to use for this instance of local-kms
    :return a running KMS server instance
    """
    global _SERVERS
    account_id = account_id or get_aws_account_id()
    with _LOCKS[account_id]:
        if account_id not in _SERVERS:
            if not _SERVERS.get(account_id):
                _SERVERS[account_id] = local_kms_server.create_local_kms_server(
                    account_id=account_id, persist_path=persist_path
                )

            _SERVERS[account_id].start()
            log_startup_message("KMS")

            check_kms(account_id=account_id)

    return _SERVERS[account_id]


def check_kms(expect_shutdown=False, print_error=False, account_id: str = DEFAULT_AWS_ACCOUNT_ID):
    if not expect_shutdown:
        assert _SERVERS.get(account_id)

    try:
        _SERVERS[account_id].wait_is_up()
    except Exception as e:
        if print_error:
            LOG.error("local-kms health check failed: %s", e)


def get_server(account_id: str = DEFAULT_AWS_ACCOUNT_ID) -> Server:
    return _SERVERS.get(account_id)
