import os
import json
import logging
import platform
import traceback
import requests
from localstack import config
from localstack.services import install
from localstack.constants import MODULE_MAIN_PATH, INSTALL_DIR_INFRA
from localstack.utils.aws import aws_stack
from localstack.utils.common import chmod_r, mkdir, get_free_tcp_port, replace_in_file, to_str, download
from localstack.services.infra import start_proxy_for_service, do_run, log_startup_message

LOGGER = logging.getLogger(__name__)

KINESIS_MOCK_RELEASES = 'https://api.github.com/repos/etspaceman/kinesis-mock/releases/tags/0.0.16'


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
    target_dir = os.path.join(INSTALL_DIR_INFRA, 'kinesis-mock')

    machine = platform.machine().lower()
    system = platform.system().lower()

    if machine == 'x86_64' or machine == 'amd64':
        if system == 'windows':
            target_file_name = 'kinesis-mock-mostly-static.exe'
        elif system == 'linux':
            target_file_name = 'kinesis-mock-linux-amd64-static'
        elif system == 'darwin':
            target_file_name = 'kinesis-mock-macos-amd64-dynamic'
        else:
            target_file_name = 'kinesis-mock.jar'
    else:
        target_file_name = 'kinesis-mock.jar'

    target_file = os.path.join(target_dir, target_file_name)
    if not os.path.exists(target_file):
        response = requests.get(KINESIS_MOCK_RELEASES)
        content = json.loads(to_str(response.content))
        assets = content.get('assets', [])
        filtered = [x for x in assets if x['name'] == target_file_name]
        archive_url = filtered[0].get('browser_download_url')
        download(archive_url, target_file)
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
        log_level = config.LS_LOG.upper
    log_level_param = 'LOG_LEVEL=%s' % (log_level)
    latency = config.KINESIS_LATENCY + 'ms'
    latency_param = 'CREATE_STREAM_DURATION=%s DELETE_STREAM_DURATION=%s REGISTER_STREAM_CONSUMER_DURATION=%s ' \
        'START_STREAM_ENCRYPTION_DURATION=%s STOP_STREAM_ENCRYPTION_DURATION=%s ' \
        'DEREGISTER_STREAM_CONSUMER_DURATION=%s MERGE_SHARDS_DURATION=%s SPLIT_SHARD_DURATION=%s ' \
        'UPDATE_SHARD_COUNT_DURATION=%s' \
        % (latency, latency, latency, latency, latency, latency, latency, latency, latency)
    if target_file_name.endswith('.jar'):
        cmd = 'KINESIS_MOCK_HTTP1_PLAIN_PORT=%s SHARD_LIMIT=%s %s %s %s java -XX:+UseG1GC -jar %s' \
            % (backend_port, config.KINESIS_SHARD_LIMIT, latency_param, kinesis_data_dir_param,
            log_level_param, target_file)
    else:
        chmod_r(target_file, 0o777)
        cmd = 'KINESIS_MOCK_HTTP1_PLAIN_PORT=%s SHARD_LIMIT=%s %s %s %s %s --gc=G1' \
            % (backend_port, config.KINESIS_SHARD_LIMIT, latency_param, kinesis_data_dir_param,
            log_level_param, target_file)
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
