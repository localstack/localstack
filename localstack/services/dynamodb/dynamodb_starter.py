import logging
import os

from localstack import config
from localstack.constants import MODULE_MAIN_PATH
from localstack.services import install
from localstack.services.dynamodb import dynamodb_listener
from localstack.services.infra import do_run, log_startup_message, start_proxy_for_service
from localstack.utils.aws import aws_stack
from localstack.utils.common import (
    get_free_tcp_port,
    mkdir,
    wait_for_port_closed,
    wait_for_port_open,
)

LOGGER = logging.getLogger(__name__)

# backend service port (updated on startup)
PORT_DYNAMODB_BACKEND = None

# todo: will be replaced with plugin mechanism
PROCESS_THREAD = None


def check_dynamodb(expect_shutdown=False, print_error=False):
    out = None
    try:
        # wait for backend port to be opened
        wait_for_port_open(PORT_DYNAMODB_BACKEND, http_path="/", expect_success=False, sleep_time=1)
        # check DynamoDB
        endpoint_url = f"http://127.0.0.1:{PORT_DYNAMODB_BACKEND}"
        out = aws_stack.connect_to_service("dynamodb", endpoint_url=endpoint_url).list_tables()
    except Exception:
        if print_error:
            LOGGER.exception("DynamoDB health check failed")
    if expect_shutdown:
        assert out is None
    else:
        assert isinstance(out["TableNames"], list)


def start_dynamodb(port=None, asynchronous=False, update_listener=None):
    global PROCESS_THREAD, PORT_DYNAMODB_BACKEND
    PORT_DYNAMODB_BACKEND = get_free_tcp_port()
    port = port or config.PORT_DYNAMODB
    install.install_dynamodb_local()
    ddb_data_dir_param = "-inMemory"
    if config.DATA_DIR:
        ddb_data_dir = "%s/dynamodb" % config.DATA_DIR
        mkdir(ddb_data_dir)
        # as the service command cds into a different directory, the absolute
        # path of the DATA_DIR is needed as the -dbPath
        absolute_path = os.path.abspath(ddb_data_dir)
        ddb_data_dir_param = "-dbPath %s" % absolute_path
    cmd = (
        "cd %s/infra/dynamodb/; java -Djava.library.path=./DynamoDBLocal_lib "
        + "-Xmx%s -jar DynamoDBLocal.jar -port %s %s"
    ) % (
        MODULE_MAIN_PATH,
        config.DYNAMODB_HEAP_SIZE,
        PORT_DYNAMODB_BACKEND,
        ddb_data_dir_param,
    )
    log_startup_message("DynamoDB")
    start_proxy_for_service(
        "dynamodb",
        port,
        backend_port=PORT_DYNAMODB_BACKEND,
        update_listener=update_listener,
    )
    # todo: extract reference from do_run (should return pid)
    PROCESS_THREAD = do_run(cmd, asynchronous, auto_restart=True)
    return PROCESS_THREAD


def restart_dynamodb():
    LOGGER.debug("Restarting DynamoDB process ...")
    PROCESS_THREAD.stop()
    wait_for_port_closed(PORT_DYNAMODB_BACKEND)
    start_dynamodb(asynchronous=True, update_listener=dynamodb_listener.UPDATE_DYNAMODB)
