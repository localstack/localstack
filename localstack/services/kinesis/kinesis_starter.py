import logging
import traceback
from localstack import config
from localstack.utils.aws import aws_stack
from localstack.utils.common import mkdir, get_free_tcp_port, edge_ports_info
from localstack.services import install
from localstack.services.infra import start_proxy_for_service, do_run
from localstack.services.install import ROOT_PATH

LOGGER = logging.getLogger(__name__)


def start_kinesis(port=None, asynchronous=False, update_listener=None):
    port = port or config.PORT_KINESIS
    install.install_kinesalite()
    backend_port = get_free_tcp_port()
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
    print('Starting mock Kinesis service on %s ...' % edge_ports_info())
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
