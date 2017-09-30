import logging
import traceback
from localstack.config import PORT_DYNAMODB, DATA_DIR
from localstack.constants import DEFAULT_PORT_DYNAMODB_BACKEND
from localstack.utils.aws import aws_stack
from localstack.utils.common import mkdir
from localstack.services import install
from localstack.services.infra import get_service_protocol, start_proxy_for_service, do_run
from localstack.services.install import ROOT_PATH

LOGGER = logging.getLogger(__name__)


def check_dynamodb(expect_shutdown=False, print_error=False):
    out = None
    try:
        # check DynamoDB
        out = aws_stack.connect_to_service(service_name='dynamodb').list_tables()
    except Exception as e:
        if print_error:
            LOGGER.error('DynamoDB health check failed: %s %s' % (e, traceback.format_exc()))
    if expect_shutdown:
        assert out is None
    else:
        assert isinstance(out['TableNames'], list)


def start_dynamodb(port=PORT_DYNAMODB, async=False, update_listener=None):
    install.install_dynamodb_local()
    backend_port = DEFAULT_PORT_DYNAMODB_BACKEND
    ddb_data_dir_param = '-inMemory'
    if DATA_DIR:
        ddb_data_dir = '%s/dynamodb' % DATA_DIR
        mkdir(ddb_data_dir)
        ddb_data_dir_param = '-dbPath %s' % ddb_data_dir
    cmd = ('cd %s/infra/dynamodb/; java -Djava.library.path=./DynamoDBLocal_lib ' +
        '-jar DynamoDBLocal.jar -sharedDb -port %s %s') % (ROOT_PATH, backend_port, ddb_data_dir_param)
    print('Starting mock DynamoDB (%s port %s)...' % (get_service_protocol(), port))
    start_proxy_for_service('dynamodb', port, backend_port, update_listener)
    return do_run(cmd, async)
