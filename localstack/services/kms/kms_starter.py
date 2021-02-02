import logging
from localstack import config
from localstack.constants import TEST_AWS_ACCOUNT_ID
from localstack.utils.common import get_arch, get_free_tcp_port, wait_for_port_open
from localstack.services.infra import start_proxy_for_service, do_run, log_startup_message
from localstack.services.install import INSTALL_PATH_KMS_BINARY_PATTERN

LOG = logging.getLogger(__name__)


def start_kms(port=None, backend_port=None, asynchronous=None, update_listener=None):
    port = port or config.PORT_KMS
    backend_port = get_free_tcp_port()
    kms_binary = INSTALL_PATH_KMS_BINARY_PATTERN.replace('<arch>', get_arch())
    log_startup_message('KMS')
    start_proxy_for_service('kms', port, backend_port, update_listener)
    env_vars = {
        'PORT': str(backend_port),
        'KMS_REGION': config.DEFAULT_REGION,
        'REGION': config.DEFAULT_REGION,
        'KMS_ACCOUNT_ID': TEST_AWS_ACCOUNT_ID,
        'ACCOUNT_ID': TEST_AWS_ACCOUNT_ID
    }
    result = do_run(kms_binary, asynchronous, env_vars=env_vars)
    wait_for_port_open(backend_port)
    return result
