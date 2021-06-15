import os
import json
import logging
import traceback
import requests
import struct
from sys import platform
from localstack import config
from localstack.services import install
from localstack.constants import MODULE_MAIN_PATH, INSTALL_DIR_INFRA
from localstack.utils.aws import aws_stack
from localstack.utils.common import chmod_r, mkdir, get_free_tcp_port, replace_in_file, to_str, download
from localstack.services.infra import start_proxy_for_service, do_run, log_startup_message

LOGGER = logging.getLogger(__name__)

KINESIS_MOCK_RELEASES = 'https://api.github.com/repos/etspaceman/kinesis-mock/releases/latest'

# Kinesis provider - either "kinesis-mock" or "kinesalite"
KINESIS_PROVIDER = os.environ.get('KINESIS_PROVIDER') or 'kinesis-mock'


def apply_patches_kinesalite():
    files = [
        '%s/node_modules/kinesalite/validations/decreaseStreamRetentionPeriod.js',
        '%s/node_modules/kinesalite/validations/increaseStreamRetentionPeriod.js'
    ]
    for file_path in files:
        file_path = file_path % MODULE_MAIN_PATH
        replace_in_file('lessThanOrEqual: 168', 'lessThanOrEqual: 8760', file_path)


def start_kinesis(port=None, asynchronous=False, update_listener=None):
    if KINESIS_PROVIDER == 'kinesis-mock':
        return start_kinesis_mock(port=port, asynchronous=asynchronous, update_listener=update_listener)
    if KINESIS_PROVIDER == 'kinesalite':
        return start_kinesalite(port=port, asynchronous=asynchronous, update_listener=update_listener)
    raise Exception('Unsupported Kinesis provider "%s"' % KINESIS_PROVIDER)


def start_kinesis_mock(port=None, asynchronous=False, update_listener=None):
    target_dir = os.path.join(INSTALL_DIR_INFRA, 'kinesis-mock')

    if config.is_in_docker:
        target_file_name = 'kinesis-mock-linux-amd64-static'
    else:
        target_file_name = 'kinesis-mock.jar'

    target_file = os.path.join(target_dir, target_file_name)
    if not os.path.exists(target_file):
        response = requests.get(KINESIS_MOCK_RELEASES)
        content = json.loads(to_str(response.content))
        archive_url = content.get('assets', [])[0].get('browser_download_url')
        download(archive_url, target_file)
    chmod_r(target_file, 0o777)
    port = port or config.PORT_KINESIS
    backend_port = get_free_tcp_port()
    kinesis_data_dir_param = ''
    if config.DATA_DIR:
        kinesis_data_dir = '%s/kinesis' % config.DATA_DIR
        mkdir(kinesis_data_dir)
        kinesis_data_dir_param = 'SHOULD_PERSIST_DATA=true PERSIST_PATH=%s' % kinesis_data_dir
    if target_file_name.endswith('.jar'):
        cmd = 'KINESIS_MOCK_HTTP1_PLAIN_PORT=%s SHARD_LIMIT=%s %s java -XX:+UseG1GC -jar %s' \
            % (backend_port, config.KINESIS_SHARD_LIMIT, kinesis_data_dir_param, target_file)
    else:
        cmd = 'KINESIS_MOCK_HTTP1_PLAIN_PORT=%s SHARD_LIMIT=%s %s %s --gc=G1' \
            % (backend_port, config.KINESIS_SHARD_LIMIT, kinesis_data_dir_param, target_file)
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
