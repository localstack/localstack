import logging
import threading
import time

from localstack import config
from localstack.constants import MODULE_MAIN_PATH
from localstack.services import install
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

LOGGER = logging.getLogger(__name__)

# event to indicate that the kinesis backend service has stopped (the terminal command has returned)
kinesis_stopped = threading.Event()

# todo: will be replaced with plugin mechanism
PROCESS_THREAD = None

PORT_KINESIS_BACKEND = None


def apply_patches_kinesalite():
    files = [
        "%s/node_modules/kinesalite/validations/decreaseStreamRetentionPeriod.js",
        "%s/node_modules/kinesalite/validations/increaseStreamRetentionPeriod.js",
    ]
    for file_path in files:
        file_path = file_path % MODULE_MAIN_PATH
        replace_in_file("lessThanOrEqual: 168", "lessThanOrEqual: 8760", file_path)


def start_kinesis(port=None, asynchronous=False, update_listener=None):
    port = port or config.PORT_KINESIS
    if config.KINESIS_PROVIDER == "kinesis-mock":
        return start_kinesis_mock(
            port=port, asynchronous=asynchronous, update_listener=update_listener
        )
    elif config.KINESIS_PROVIDER == "kinesalite":
        return start_kinesalite(
            port=port, asynchronous=asynchronous, update_listener=update_listener
        )
    else:
        raise Exception('Unsupported Kinesis provider "%s"' % config.KINESIS_PROVIDER)


def _run_proxy_and_command(cmd, port, backend_port, update_listener, asynchronous):
    global PROCESS_THREAD
    log_startup_message("Kinesis")
    start_proxy_for_service("kinesis", port, backend_port, update_listener)

    # TODO: generalize into service manager once it is introduced
    try:
        PROCESS_THREAD = do_run(cmd, asynchronous)
    finally:
        if asynchronous:

            def _return_listener(*_):
                try:
                    ret_code = PROCESS_THREAD.result_future.result()
                    if ret_code not in [0, None]:
                        LOGGER.error("kinesis terminated with return code %s", ret_code)
                finally:
                    kinesis_stopped.set()

            start_thread(_return_listener)
        else:
            kinesis_stopped.set()

    return PROCESS_THREAD


def start_kinesis_mock(port=None, asynchronous=False, update_listener=None):
    kinesis_mock_bin = install.install_kinesis_mock()

    backend_port = get_free_tcp_port()
    global PORT_KINESIS_BACKEND
    PORT_KINESIS_BACKEND = backend_port
    kinesis_data_dir_param = ""
    if config.DATA_DIR:
        kinesis_data_dir = "%s/kinesis" % config.DATA_DIR
        mkdir(kinesis_data_dir)
        kinesis_data_dir_param = "SHOULD_PERSIST_DATA=true PERSIST_PATH=%s" % kinesis_data_dir
    if not config.LS_LOG:
        log_level = "INFO"
    elif config.LS_LOG == "warning":
        log_level = "WARN"
    else:
        log_level = config.LS_LOG.upper()
    log_level_param = "LOG_LEVEL=%s" % log_level
    latency = config.KINESIS_LATENCY + "ms"
    latency_param = (
        "CREATE_STREAM_DURATION={l} DELETE_STREAM_DURATION={l} REGISTER_STREAM_CONSUMER_DURATION={l} "
        "START_STREAM_ENCRYPTION_DURATION={l} STOP_STREAM_ENCRYPTION_DURATION={l} "
        "DEREGISTER_STREAM_CONSUMER_DURATION={l} MERGE_SHARDS_DURATION={l} SPLIT_SHARD_DURATION={l} "
        "UPDATE_SHARD_COUNT_DURATION={l}"
    ).format(l=latency)

    if config.KINESIS_INITIALIZE_STREAMS != "":
        initialize_streams_param = "INITIALIZE_STREAMS=%s" % config.KINESIS_INITIALIZE_STREAMS
    else:
        initialize_streams_param = ""

    if kinesis_mock_bin.endswith(".jar"):
        cmd = "KINESIS_MOCK_PLAIN_PORT=%s SHARD_LIMIT=%s %s %s %s %s java -XX:+UseG1GC -jar %s" % (
            backend_port,
            config.KINESIS_SHARD_LIMIT,
            latency_param,
            kinesis_data_dir_param,
            log_level_param,
            initialize_streams_param,
            kinesis_mock_bin,
        )
    else:
        chmod_r(kinesis_mock_bin, 0o777)
        cmd = "KINESIS_MOCK_PLAIN_PORT=%s SHARD_LIMIT=%s %s %s %s %s %s --gc=G1" % (
            backend_port,
            config.KINESIS_SHARD_LIMIT,
            latency_param,
            kinesis_data_dir_param,
            log_level_param,
            initialize_streams_param,
            kinesis_mock_bin,
        )

    return _run_proxy_and_command(
        cmd=cmd,
        port=port,
        backend_port=backend_port,
        update_listener=update_listener,
        asynchronous=asynchronous,
    )


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
    if config.DATA_DIR:
        kinesis_data_dir = "%s/kinesis" % config.DATA_DIR
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


def check_kinesis(expect_shutdown=False, print_error=False):
    if expect_shutdown is False and kinesis_stopped.is_set():
        raise AssertionError("kinesis backend has stopped")

    out = None
    try:
        # check Kinesis
        wait_for_port_open(PORT_KINESIS_BACKEND, http_path="/", expect_success=False, sleep_time=1)
        endpoint_url = f"http://127.0.0.1:{PORT_KINESIS_BACKEND}"
        out = aws_stack.connect_to_service(
            service_name="kinesis", endpoint_url=endpoint_url
        ).list_streams()
    except Exception:
        if print_error:
            LOGGER.exception("Kinesis health check failed")

    if expect_shutdown:
        assert out is None or kinesis_stopped.is_set()
    else:
        assert not kinesis_stopped.is_set()
        assert out and isinstance(out.get("StreamNames"), list)


def restart_kinesis():
    LOGGER.debug("Restarting Kinesis process ...")
    PROCESS_THREAD.stop()
    kinesis_stopped.wait()
    kinesis_stopped.clear()
    start_kinesis(asynchronous=True, update_listener=kinesis_listener.UPDATE_KINESIS)
    # giving the process some time to startup; TODO: to be replaced with service lifecycle plugin
    time.sleep(1)
