import os
import logging
import traceback
from localstack import config
from localstack.config import LOCALSTACK_HOSTNAME, TMP_FOLDER
from localstack.utils.aws import aws_stack
from localstack.utils.common import wait_for_port_open, save_file, short_uid, TMP_FILES, get_free_tcp_port
from localstack.services.infra import start_proxy_for_service, get_service_protocol, do_run
from localstack.services.install import INSTALL_DIR_ELASTICMQ, install_elasticmq

LOG = logging.getLogger(__name__)

# backend port (configured at startup)
PORT_SQS_BACKEND = None

# max heap size allocated for the Java process
MAX_HEAP_SIZE = '256m'


def check_sqs(expect_shutdown=False, print_error=False):
    out = None
    try:
        # wait for port to be opened
        wait_for_port_open(PORT_SQS_BACKEND)
        # check SQS
        out = aws_stack.connect_to_service(service_name='sqs').list_queues()
    except Exception as e:
        if print_error:
            LOG.warning('SQS health check failed: %s %s' % (e, traceback.format_exc()))
    if expect_shutdown:
        assert out is None
    else:
        assert out.get('ResponseMetadata', {}).get('HTTPStatusCode') == 200


def start_sqs(port=None, asynchronous=False, update_listener=None):
    global PORT_SQS_BACKEND

    port = port or config.PORT_SQS
    install_elasticmq()
    PORT_SQS_BACKEND = get_free_tcp_port()
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
    """ % (LOCALSTACK_HOSTNAME, port, PORT_SQS_BACKEND)
    config_file = os.path.join(TMP_FOLDER, 'sqs.%s.conf' % short_uid())
    TMP_FILES.append(config_file)
    save_file(config_file, config_params)
    # start process
    cmd = ('java -Dconfig.file=%s -Xmx%s -jar %s/elasticmq-server.jar' % (
        config_file, MAX_HEAP_SIZE, INSTALL_DIR_ELASTICMQ))
    print('Starting mock SQS service in %s ports %s (recommended) and %s (deprecated)...' % (
        get_service_protocol(), config.EDGE_PORT, port))
    start_proxy_for_service('sqs', port, PORT_SQS_BACKEND, update_listener)
    return do_run(cmd, asynchronous)
