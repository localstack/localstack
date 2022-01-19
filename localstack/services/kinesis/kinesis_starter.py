import logging
import threading
import time
from typing import Optional

from localstack import config
from localstack.constants import MODULE_MAIN_PATH
from localstack.services import install
from localstack.services.kinesis.server import KinesisServer, create_kinesis_server
from localstack.services.infra import do_run, log_startup_message, start_proxy_for_service
from localstack.services.kinesis import kinesis_listener
from localstack.utils.aws import aws_stack
from localstack.utils.common import (
    chmod_r,
    get_free_tcp_port,
    mkdir,
    replace_in_file,
    start_thread,
    wait_for_port_open,
)

LOG = logging.getLogger(__name__)

# server singleton
_server: Optional[KinesisServer] = None

# event to indicate that the kinesis backend service has stopped (the terminal command has returned)
kinesis_stopped = threading.Event()

# todo: will be replaced with plugin mechanism
PROCESS_THREAD = None


def apply_patches_kinesalite():
    files = [
        "%s/kinesalite/validations/decreaseStreamRetentionPeriod.js",
        "%s/kinesalite/validations/increaseStreamRetentionPeriod.js",
    ]
    for file_path in files:
        file_path = file_path % install.INSTALL_DIR_NPM
        replace_in_file("lessThanOrEqual: 168", "lessThanOrEqual: 8760", file_path)


def start_kinesis(port=None, asynchronous=False, update_listener=None):
    port = port or config.PORT_KINESIS
    if config.KINESIS_PROVIDER == "kinesis-mock":
        return start_kinesis_mock(port, update_listener)
    if config.KINESIS_PROVIDER == "kinesalite":
        return start_kinesalite(
            port=port, asynchronous=asynchronous, update_listener=update_listener
        )
    raise Exception('Unsupported Kinesis provider "%s"' % config.KINESIS_PROVIDER)


def start_kinesis_mock(port=None, update_listener=None):
    global _server
    if not _server:
        _server = create_kinesis_server()

    _server.start()
    log_startup_message("Kinesis")
    start_proxy_for_service(
        "kinesis",
        port,
        backend_port=_server.port,
        update_listener=update_listener,
    )
    return _server


def start_kinesalite(port=None, asynchronous=False, update_listener=None):
    # install and apply patches
    install.install_kinesalite()
    apply_patches_kinesalite()
    # start up process
    backend_port = get_free_tcp_port()
    global PORT_KINESIS_BACKEND
    PORT_KINESIS_BACKEND = backend_port
    latency = config.KINESIS_LATENCY
    kinesis_data_dir_param = ""
    if config.dirs.data:
        kinesis_data_dir = "%s/kinesis" % config.dirs.data
        mkdir(kinesis_data_dir)
        kinesis_data_dir_param = "--path %s" % kinesis_data_dir
    cmd = (
        "%s/node_modules/kinesalite/cli.js --shardLimit %s --port %s"
        " --createStreamMs %s --deleteStreamMs %s --updateStreamMs %s %s"
    ) % (
        MODULE_MAIN_PATH,
        config.KINESIS_SHARD_LIMIT,
        backend_port,
        latency,
        latency,
        latency,
        kinesis_data_dir_param,
    )

    return _run_proxy_and_command(
        cmd=cmd,
        port=port,
        backend_port=backend_port,
        update_listener=update_listener,
        asynchronous=asynchronous,
    )

def _run_proxy_and_command(**kwargs):
    pass

def check_kinesis(expect_shutdown=False, print_error=False):
    out = None

    if not expect_shutdown:
        assert _server

    try:
        _server.wait_is_up()
        out = aws_stack.connect_to_service(
            service_name="kinesis", endpoint_url=_server.url
        ).list_streams()
    except Exception:
        if print_error:
            LOG.exception("Kinesis health check failed")
    if expect_shutdown:
        assert out is None
    else:
        assert out is not None and isinstance(out.get("StreamNames"), list)

def restart_kinesis():
    if PROCESS_THREAD:
        LOG.debug("Restarting Kinesis process ...")
        PROCESS_THREAD.stop()
        kinesis_stopped.wait()
        kinesis_stopped.clear()
        start_kinesis(asynchronous=True, update_listener=kinesis_listener.UPDATE_KINESIS)
        # giving the process some time to startup; TODO: to be replaced with service lifecycle plugin
        time.sleep(1)
