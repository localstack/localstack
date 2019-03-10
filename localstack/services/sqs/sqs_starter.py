import os
import logging
from localstack import config
from localstack.config import LOCALSTACK_HOSTNAME, TMP_FOLDER
from localstack.constants import DEFAULT_PORT_SQS_BACKEND
from localstack.utils.common import save_file, short_uid, TMP_FILES
from localstack.services.infra import start_proxy_for_service, get_service_protocol, do_run
from localstack.services.install import INSTALL_DIR_ELASTICMQ, install_elasticmq

# max heap size allocated for the Java process
MAX_HEAP_SIZE = '256m'

LOGGER = logging.getLogger(__name__)


def start_sqs(port=None, asynchronous=False, update_listener=None):
    port = port or config.PORT_SQS
    install_elasticmq()
    backend_port = DEFAULT_PORT_SQS_BACKEND
    # create config file
    config_params = """
    include classpath("application.conf")
    node-address {
        protocol = http
        host = "%s"
        port = %s
        context-path = ""
    }
    rest-sqs {
        enabled = true
        bind-port = %s
        bind-hostname = "0.0.0.0"
        sqs-limits = strict
    }
    """ % (LOCALSTACK_HOSTNAME, port, backend_port)
    config_file = os.path.join(TMP_FOLDER, 'sqs.%s.conf' % short_uid())
    TMP_FILES.append(config_file)
    save_file(config_file, config_params)
    # start process
    cmd = ('java -Dconfig.file=%s -Xmx%s -jar %s/elasticmq-server.jar' % (
        config_file, MAX_HEAP_SIZE, INSTALL_DIR_ELASTICMQ))
    print('Starting mock SQS (%s port %s)...' % (get_service_protocol(), port))
    start_proxy_for_service('sqs', port, backend_port, update_listener)
    return do_run(cmd, asynchronous)
