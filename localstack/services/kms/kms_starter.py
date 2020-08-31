import logging
from localstack import config
from localstack.constants import TEST_AWS_ACCOUNT_ID
from localstack.utils.common import get_arch, get_free_tcp_port
from localstack.services.infra import (
    get_service_protocol, start_proxy_for_service, do_run)
from localstack.services.install import INSTALL_PATH_KMS_BINARY_PATTERN

LOG = logging.getLogger(__name__)


def start_kms(port=None, backend_port=None, asynchronous=None, update_listener=None):
    port = port or config.PORT_KMS
    backend_port = get_free_tcp_port()
    kms_binary = INSTALL_PATH_KMS_BINARY_PATTERN.replace('<arch>', get_arch())
    print('Starting mock KMS service on %s port %s ...' % (
        get_service_protocol(), config.EDGE_PORT))
    start_proxy_for_service('kms', port, backend_port, update_listener)
    env_vars = {
        'PORT': str(backend_port),
        'KMS_REGION': config.DEFAULT_REGION,
        'REGION': config.DEFAULT_REGION,
        'KMS_ACCOUNT_ID': TEST_AWS_ACCOUNT_ID,
        'ACCOUNT_ID': TEST_AWS_ACCOUNT_ID
    }
    return do_run(kms_binary, asynchronous, env_vars=env_vars)
