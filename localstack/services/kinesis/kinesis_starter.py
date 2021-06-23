import logging
import traceback
from localstack import config
from localstack.services import install
from localstack.constants import MODULE_MAIN_PATH
from localstack.utils.aws import aws_stack
from localstack.utils.common import chmod_r, mkdir, get_free_tcp_port, replace_in_file
from localstack.services.infra import start_proxy_for_service, do_run, log_startup_message

LOGGER = logging.getLogger(__name__)

KINESIS_MOCK_RELEASES = 'https://api.github.com/repos/etspaceman/kinesis-mock/releases/tags/0.1.0'


def apply_patches_kinesalite():
    files = [
        '%s/node_modules/kinesalite/validations/decreaseStreamRetentionPeriod.js',
        '%s/node_modules/kinesalite/validations/increaseStreamRetentionPeriod.js'
    ]
    for file_path in files:
        file_path = file_path % MODULE_MAIN_PATH
        replace_in_file('lessThanOrEqual: 168', 'lessThanOrEqual: 8760', file_path)


def start_kinesis(port=None, asynchronous=False, update_listener=None):
    if config.KINESIS_PROVIDER == 'kinesis-mock':
        return start_kinesis_mock(port=port, asynchronous=asynchronous, update_listener=update_listener)
    elif config.KINESIS_PROVIDER == 'kinesalite':
        return start_kinesalite(port=port, asynchronous=asynchronous, update_listener=update_listener)
    else:
        raise Exception('Unsupported Kinesis provider "%s"' % config.KINESIS_PROVIDER)


def start_kinesis_mock(port=None, asynchronous=False, update_listener=None):
    kinesis_mock_bin = install.install_kinesis_mock()

    port = port or config.PORT_KINESIS
    backend_port = get_free_tcp_port()
    kinesis_data_dir_param = ''
    if config.DATA_DIR:
        kinesis_data_dir = '%s/kinesis' % config.DATA_DIR
        mkdir(kinesis_data_dir)
        kinesis_data_dir_param = 'SHOULD_PERSIST_DATA=true PERSIST_PATH=%s' % kinesis_data_dir
    if not config.LS_LOG:
        log_level = 'INFO'
    elif config.LS_LOG == 'warning':
        log_level = 'WARN'
    else:
        log_level = config.LS_LOG.upper()
    log_level_param = 'LOG_LEVEL=%s' % log_level
    latency = config.KINESIS_LATENCY + 'ms'
    latency_param = 'CREATE_STREAM_DURATION=%s DELETE_STREAM_DURATION=%s REGISTER_STREAM_CONSUMER_DURATION=%s ' \
        'START_STREAM_ENCRYPTION_DURATION=%s STOP_STREAM_ENCRYPTION_DURATION=%s ' \
        'DEREGISTER_STREAM_CONSUMER_DURATION=%s MERGE_SHARDS_DURATION=%s SPLIT_SHARD_DURATION=%s ' \
        'UPDATE_SHARD_COUNT_DURATION=%s' \
        % (latency, latency, latency, latency, latency, latency, latency, latency, latency)

    if config.KINESIS_INITIALIZE_STREAMS != '':
        initialize_streams_param = 'INITIALIZE_STREAMS=%s' % (config.KINESIS_INITIALIZE_STREAMS)
    else:
        initialize_streams_param = ''

    if kinesis_mock_bin.endswith('.jar'):
        cmd = 'KINESIS_MOCK_PLAIN_PORT=%s SHARD_LIMIT=%s %s %s %s %s java -XX:+UseG1GC -jar %s' \
              % (backend_port, config.KINESIS_SHARD_LIMIT, latency_param, kinesis_data_dir_param,
                 log_level_param, initialize_streams_param, kinesis_mock_bin)
    else:
        chmod_r(kinesis_mock_bin, 0o777)
        cmd = 'KINESIS_MOCK_PLAIN_PORT=%s SHARD_LIMIT=%s %s %s %s %s %s --gc=G1' \
              % (backend_port, config.KINESIS_SHARD_LIMIT, latency_param, kinesis_data_dir_param,
                 log_level_param, initialize_streams_param, kinesis_mock_bin)
    LOGGER.info('starting kinesis-mock proxy %d:%d with cmd: %s', port, backend_port, cmd)
    start_proxy_for_service('kinesis', port, backend_port, update_listener)
    return do_run(cmd, asynchronous)


def start_kinesalite(port=None, asynchronous=False, update_listener=None):
    # install and apply patches
    install.install_kinesalite()
    apply_patches_kinesalite()
    # start up process
    port = port or config.PORT_KINESIS
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
        MODULE_MAIN_PATH, config.KINESIS_SHARD_LIMIT, backend_port,
        latency, latency, latency, kinesis_data_dir_param
    )
    log_startup_message('Kinesis')
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
