import logging
import os
import traceback
from localstack import config
from localstack.services import install
from localstack.utils.aws import aws_stack
from localstack.utils.common import mkdir, wait_for_port_open, get_free_tcp_port, edge_ports_info
from localstack.services.infra import start_proxy_for_service, do_run
from localstack.services.install import ROOT_PATH

LOGGER = logging.getLogger(__name__)

# backend service port (updated on startup)
PORT_DYNAMODB_BACKEND = None


def check_dynamodb(expect_shutdown=False, print_error=False):
    out = None
    try:
        # wait for backend port to be opened
        wait_for_port_open(PORT_DYNAMODB_BACKEND, http_path='/', expect_success=False, sleep_time=1)
        # check DynamoDB
        out = aws_stack.connect_to_service('dynamodb').list_tables()
    except Exception as e:
        if print_error:
            LOGGER.error('DynamoDB health check failed: %s %s' % (e, traceback.format_exc()))
    if expect_shutdown:
        assert out is None
    else:
        assert isinstance(out['TableNames'], list)


def start_dynamodb(port=None, asynchronous=False, update_listener=None):
    global PORT_DYNAMODB_BACKEND
    PORT_DYNAMODB_BACKEND = get_free_tcp_port()
    port = port or config.PORT_DYNAMODB
    install.install_dynamodb_local()
    ddb_data_dir_param = '-inMemory'
    if config.DATA_DIR:
        ddb_data_dir = '%s/dynamodb' % config.DATA_DIR
        mkdir(ddb_data_dir)
        # as the service command cds into a different directory, the absolute
        # path of the DATA_DIR is needed as the -dbPath
        absolute_path = os.path.abspath(ddb_data_dir)
        ddb_data_dir_param = '-dbPath %s' % absolute_path
    cmd = ('cd %s/infra/dynamodb/; java -Djava.library.path=./DynamoDBLocal_lib ' +
        '-Xmx%s -jar DynamoDBLocal.jar -sharedDb -port %s %s') % (
        ROOT_PATH, config.DYNAMODB_HEAP_SIZE, PORT_DYNAMODB_BACKEND, ddb_data_dir_param)
    print('Starting mock DynamoDB service on %s ...' % edge_ports_info())
    start_proxy_for_service('dynamodb', port, backend_port=PORT_DYNAMODB_BACKEND, update_listener=update_listener)
    return do_run(cmd, asynchronous)
