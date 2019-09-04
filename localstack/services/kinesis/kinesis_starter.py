import logging
import traceback
from localstack import config
from localstack.constants import DEFAULT_PORT_KINESIS_BACKEND
from localstack.utils.aws import aws_stack
from localstack.utils.common import mkdir
from localstack.services import install
from localstack.services.infra import get_service_protocol, start_proxy_for_service, do_run
from localstack.services.install import ROOT_PATH

LOGGER = logging.getLogger(__name__)


def start_kinesis(port=None, asynchronous=False, update_listener=None):
    port = port or config.PORT_KINESIS
    install.install_kinesalite()
    backend_port = DEFAULT_PORT_KINESIS_BACKEND
    latency = config.KINESIS_LATENCY
    kinesis_data_dir_param = ''
    if config.DATA_DIR:
        kinesis_data_dir = '%s/kinesis' % config.DATA_DIR
        mkdir(kinesis_data_dir)
        kinesis_data_dir_param = '--path %s' % kinesis_data_dir
    cmd = (
        '%s/node_modules/kinesalite/cli.js --shardLimit %s --port %s'
        ' --createStreamMs %s --deleteStreamMs %s --updateStreamMs %s %s'
    ) % (
        ROOT_PATH, config.KINESIS_SHARD_LIMIT, backend_port,
        latency, latency, latency, kinesis_data_dir_param
    )
    print('Starting mock Kinesis (%s port %s)...' % (get_service_protocol(), port))
    start_proxy_for_service('kinesis', port, backend_port, update_listener)
    return do_run(cmd, asynchronous)


def check_kinesis(expect_shutdown=False, print_error=False):
    out = None
    try:
        # check Kinesis
        out = aws_stack.connect_to_service(service_name='kinesis').list_streams()
    except Exception as e:
        if print_error:
            LOGGER.error('Kinesis health check failed: %s %s' % (e, traceback.format_exc()))
    if expect_shutdown:
        assert out is None
    else:
        assert isinstance(out['StreamNames'], list)
