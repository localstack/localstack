import logging
import platform

from localstack import config
from localstack.aws.accounts import get_aws_account_id
from localstack.services.infra import do_run, log_startup_message, start_proxy_for_service
from localstack.services.install import INSTALL_PATH_KMS_BINARY_PATTERN
from localstack.utils.common import get_arch, get_free_tcp_port, wait_for_port_open

LOG = logging.getLogger(__name__)


def start_kms_local(port=None, backend_port=None, asynchronous=None, update_listener=None):
    port = port or config.service_port("kms")
    backend_port = get_free_tcp_port()
    kms_binary = INSTALL_PATH_KMS_BINARY_PATTERN.replace(
        "<arch>", f"{platform.system().lower()}-{get_arch()}"
    )
    log_startup_message("KMS")
    start_proxy_for_service("kms", port, backend_port, update_listener)
    account_id = get_aws_account_id()
    env_vars = {
        "PORT": str(backend_port),
        "KMS_REGION": config.DEFAULT_REGION,
        "REGION": config.DEFAULT_REGION,
        "KMS_ACCOUNT_ID": account_id,
        "ACCOUNT_ID": account_id,
    }
    if config.PERSISTENCE:
        env_vars["KMS_DATA_PATH"] = config.dirs.data
    result = do_run(kms_binary, asynchronous, env_vars=env_vars)
    wait_for_port_open(backend_port)
    return result
