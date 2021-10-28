import logging
import os

from localstack import config
from localstack.constants import TEST_AWS_ACCOUNT_ID
from localstack.services.infra import (
    do_run,
    log_startup_message,
    start_moto_server,
    start_proxy_for_service,
)
from localstack.services.install import INSTALL_PATH_KMS_BINARY_PATTERN
from localstack.utils.common import get_arch, get_free_tcp_port, wait_for_port_open

LOG = logging.getLogger(__name__)

# KMS provider - can be either "local-kms" or "moto"
KMS_PROVIDER = (os.environ.get("KMS_PROVIDER") or "").strip() or "moto"


def start_kms_local(port=None, backend_port=None, asynchronous=None, update_listener=None):
    port = port or config.PORT_KMS
    backend_port = get_free_tcp_port()
    kms_binary = INSTALL_PATH_KMS_BINARY_PATTERN.replace("<arch>", get_arch())
    log_startup_message("KMS")
    start_proxy_for_service("kms", port, backend_port, update_listener)
    env_vars = {
        "PORT": str(backend_port),
        "KMS_REGION": config.DEFAULT_REGION,
        "REGION": config.DEFAULT_REGION,
        "KMS_ACCOUNT_ID": TEST_AWS_ACCOUNT_ID,
        "ACCOUNT_ID": TEST_AWS_ACCOUNT_ID,
    }
    if config.DATA_DIR:
        env_vars["KMS_DATA_PATH"] = config.DATA_DIR
    result = do_run(kms_binary, asynchronous, env_vars=env_vars)
    wait_for_port_open(backend_port)
    return result


def start_kms_moto(port=None, backend_port=None, asynchronous=None, update_listener=None):
    port = port or config.PORT_KMS
    return start_moto_server(
        "kms",
        port,
        name="KMS",
        asynchronous=asynchronous,
        update_listener=update_listener,
    )


def start_kms(port=None, backend_port=None, asynchronous=None, update_listener=None):
    providers = {
        "local-kms": start_kms_local,
        "moto": start_kms_moto,
    }
    provider_func = providers.get(KMS_PROVIDER)
    if not provider_func:
        raise Exception("Unsupported KMS_PROVIDER '%s' specified" % KMS_PROVIDER)
    return provider_func(
        port=port,
        backend_port=backend_port,
        asynchronous=asynchronous,
        update_listener=update_listener,
    )
