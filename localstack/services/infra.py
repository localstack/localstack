import logging
import os
import re
import signal
import subprocess
import sys
import threading
import time
import traceback

import boto3
from moto import core as moto_core

from localstack import config, constants
from localstack.constants import (
    DEFAULT_SERVICE_PORTS,
    ENV_DEV,
    LOCALSTACK_INFRA_PROCESS,
    LOCALSTACK_VENV_FOLDER,
)
from localstack.services import generic_proxy, install
from localstack.services.awslambda import lambda_api
from localstack.services.cloudformation import cloudformation_api
from localstack.services.dynamodbstreams import dynamodbstreams_api
from localstack.services.firehose import firehose_api
from localstack.services.generic_proxy import start_proxy_server
from localstack.services.plugins import (
    SERVICE_PLUGINS,
    check_infra,
    record_service_health,
    wait_for_infra_shutdown,
)
from localstack.utils import common, config_listener, persistence
from localstack.utils.analytics import event_publisher
from localstack.utils.analytics.profiler import log_duration
from localstack.utils.bootstrap import canonicalize_api_names, in_ci, load_plugins, setup_logging
from localstack.utils.cli import print_version
from localstack.utils.common import (
    TMP_THREADS,
    ShellCommandThread,
    edge_ports_info,
    get_free_tcp_port,
    in_docker,
    is_linux,
    is_port_open,
    run,
    start_thread,
)
from localstack.utils.server import multiserver
from localstack.utils.testutil import is_local_test_mode

# flag to indicate whether signal handlers have been set up already
SIGNAL_HANDLERS_SETUP = False

# output string that indicates that the stack is ready
READY_MARKER_OUTPUT = "Ready."

# default backend host address
DEFAULT_BACKEND_HOST = "127.0.0.1"

# maps ports to proxy listener details
PROXY_LISTENERS = {}

# set up logger
LOG = logging.getLogger(__name__)

# event flag indicating the the infrastructure has been started and that the ready marker has been printed
INFRA_READY = threading.Event()

# event flag indicating that the infrastructure has been shut down
SHUTDOWN_INFRA = threading.Event()


# Start config update backdoor
config_listener.start_listener()

# -----------------
# API ENTRY POINTS
# -----------------


def start_sns(port=None, asynchronous=False, update_listener=None):
    port = port or config.PORT_SNS
    return start_moto_server(
        "sns",
        port,
        name="SNS",
        asynchronous=asynchronous,
        update_listener=update_listener,
    )


def start_sts(port=None, asynchronous=False):
    port = port or config.PORT_STS
    return start_moto_server("sts", port, name="STS", asynchronous=asynchronous)


def start_firehose(port=None, asynchronous=False):
    port = port or config.PORT_FIREHOSE
    return start_local_api(
        "Firehose",
        port,
        api="firehose",
        method=firehose_api.serve,
        asynchronous=asynchronous,
    )


def start_dynamodbstreams(port=None, asynchronous=False):
    port = port or config.PORT_DYNAMODBSTREAMS
    return start_local_api(
        "DynamoDB Streams",
        port,
        api="dynamodbstreams",
        method=dynamodbstreams_api.serve,
        asynchronous=asynchronous,
    )


def start_lambda(port=None, asynchronous=False):
    port = port or config.PORT_LAMBDA
    return start_local_api(
        "Lambda", port, api="lambda", method=lambda_api.serve, asynchronous=asynchronous
    )


def start_cloudformation(port=None, asynchronous=False):
    port = port or config.PORT_CLOUDFORMATION
    return start_local_api(
        "CloudFormation",
        port,
        api="cloudformation",
        method=cloudformation_api.serve,
        asynchronous=asynchronous,
    )


def start_ssm(port=None, asynchronous=False, update_listener=None):
    port = port or config.PORT_SSM
    return start_moto_server(
        "ssm",
        port,
        name="SSM",
        asynchronous=asynchronous,
        update_listener=update_listener,
    )


# ---------------
# HELPER METHODS
# ---------------


def patch_urllib3_connection_pool(**constructor_kwargs):
    """
    Override the default parameters of HTTPConnectionPool, e.g., set the pool size via maxsize=16
    """
    try:
        from urllib3 import connectionpool, poolmanager

        class MyHTTPSConnectionPool(connectionpool.HTTPSConnectionPool):
            def __init__(self, *args, **kwargs):
                kwargs.update(constructor_kwargs)
                super(MyHTTPSConnectionPool, self).__init__(*args, **kwargs)

        poolmanager.pool_classes_by_scheme["https"] = MyHTTPSConnectionPool

        class MyHTTPConnectionPool(connectionpool.HTTPConnectionPool):
            def __init__(self, *args, **kwargs):
                kwargs.update(constructor_kwargs)
                super(MyHTTPConnectionPool, self).__init__(*args, **kwargs)

        poolmanager.pool_classes_by_scheme["http"] = MyHTTPConnectionPool
    except Exception:
        pass


def patch_instance_tracker_meta():
    """
    Avoid instance collection for moto dashboard
    """

    def new_intance(meta, name, bases, dct):
        cls = super(moto_core.models.InstanceTrackerMeta, meta).__new__(meta, name, bases, dct)
        if name == "BaseModel":
            return cls
        cls.instances = []
        return cls

    moto_core.models.InstanceTrackerMeta.__new__ = new_intance

    def new_basemodel(cls, *args, **kwargs):
        instance = super(moto_core.models.BaseModel, cls).__new__(cls)
        return instance

    moto_core.models.BaseModel.__new__ = new_basemodel


def set_service_status(data):
    command = data.get("command")
    service = data.get("service")
    service_ports = config.parse_service_ports()
    if command == "start":
        existing = service_ports.get(service)
        port = DEFAULT_SERVICE_PORTS.get(service)
        if existing:
            status = get_service_status(service, port)
            if status == "running":
                return
        key_upper = service.upper().replace("-", "_")
        port_variable = "PORT_%s" % key_upper
        service_list = os.environ.get("SERVICES", "").strip()
        services = [e for e in re.split(r"[\s,]+", service_list) if e]
        contained = [s for s in services if s.startswith(service)]
        if not contained:
            services.append(service)
        config_listener.update_config_variable(port_variable, port)
        new_service_list = ",".join(services)
        os.environ["SERVICES"] = new_service_list
        # TODO: expensive operation - check if we need to do this here for each service, should be optimized!
        config.populate_configs()
        LOG.info("Starting service %s on port %s" % (service, port))
        SERVICE_PLUGINS[service].start(asynchronous=True)
    return {}


def get_services_status():
    result = {}
    for service, port in config.parse_service_ports().items():
        status = get_service_status(service, port)
        result[service] = {"port": port, "status": status}
    return result


def get_service_status(service, port=None):
    port = port or config.parse_service_ports().get(service)
    status = "disabled" if (port or 0) <= 0 else "running" if is_port_open(port) else "stopped"
    return status


def get_multiserver_or_free_service_port():
    if config.FORWARD_EDGE_INMEM:
        return multiserver.get_moto_server_port()
    return get_free_tcp_port()


def register_signal_handlers():
    global SIGNAL_HANDLERS_SETUP
    if SIGNAL_HANDLERS_SETUP:
        return

    # register signal handlers
    def signal_handler(sig, frame):
        LOG.debug("[shutdown] signal received %s", sig)
        stop_infra()
        if config.FORCE_SHUTDOWN:
            sys.exit(0)

    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)
    SIGNAL_HANDLERS_SETUP = True


def do_run(cmd, asynchronous, print_output=None, env_vars={}, auto_restart=False):
    sys.stdout.flush()
    if asynchronous:
        if config.DEBUG and print_output is None:
            print_output = True
        outfile = subprocess.PIPE if print_output else None
        t = ShellCommandThread(cmd, outfile=outfile, env_vars=env_vars, auto_restart=auto_restart)
        t.start()
        TMP_THREADS.append(t)
        return t
    return run(cmd, env_vars=env_vars)


def start_proxy_for_service(
    service_name, port, backend_port, update_listener, quiet=False, params={}
):
    # TODO: remove special switch for Elasticsearch (see also note in service_port(...) in config.py)
    if config.FORWARD_EDGE_INMEM and service_name != "elasticsearch":
        if backend_port:
            PROXY_LISTENERS[service_name] = (
                service_name,
                backend_port,
                update_listener,
            )
        return
    # check if we have a custom backend configured
    custom_backend_url = os.environ.get("%s_BACKEND" % service_name.upper())
    backend_url = custom_backend_url or ("http://%s:%s" % (DEFAULT_BACKEND_HOST, backend_port))
    return start_proxy(
        port,
        backend_url=backend_url,
        update_listener=update_listener,
        quiet=quiet,
        params=params,
    )


def start_proxy(port, backend_url=None, update_listener=None, quiet=False, params={}, use_ssl=None):
    use_ssl = config.USE_SSL if use_ssl is None else use_ssl
    proxy_thread = start_proxy_server(
        port=port,
        forward_url=backend_url,
        use_ssl=use_ssl,
        update_listener=update_listener,
        quiet=quiet,
        params=params,
    )
    return proxy_thread


def start_moto_server(
    key, port, name=None, backend_port=None, asynchronous=False, update_listener=None
):
    if not name:
        name = key
    log_startup_message(name)
    if not backend_port:
        if config.FORWARD_EDGE_INMEM:
            backend_port = multiserver.get_moto_server_port()
        elif config.USE_SSL or update_listener:
            backend_port = get_free_tcp_port()
    if backend_port or config.FORWARD_EDGE_INMEM:
        start_proxy_for_service(key, port, backend_port, update_listener)
    if config.BUNDLE_API_PROCESSES:
        return multiserver.start_api_server(key, backend_port or port)
    return start_moto_server_separate(
        key, port, name=name, backend_port=backend_port, asynchronous=asynchronous
    )


def start_moto_server_separate(key, port, name=None, backend_port=None, asynchronous=False):
    moto_server_cmd = "%s/bin/moto_server" % LOCALSTACK_VENV_FOLDER
    if not os.path.exists(moto_server_cmd):
        moto_server_cmd = run("which moto_server").strip()
    cmd = "VALIDATE_LAMBDA_S3=0 %s %s -p %s -H %s" % (
        moto_server_cmd,
        key,
        backend_port or port,
        constants.BIND_HOST,
    )
    return do_run(cmd, asynchronous)


def start_local_api(name, port, api, method, asynchronous=False):
    log_startup_message(name)
    if config.FORWARD_EDGE_INMEM:
        port = get_free_tcp_port()
        PROXY_LISTENERS[api] = (api, port, None)
    if asynchronous:
        thread = start_thread(method, port, quiet=True)
        return thread
    else:
        method(port)


def stop_infra():
    if common.INFRA_STOPPED:
        return
    common.INFRA_STOPPED = True

    event_publisher.fire_event(event_publisher.EVENT_STOP_INFRA)

    try:
        generic_proxy.QUIET = True
        LOG.debug("[shutdown] Cleaning up files ...")
        common.cleanup(files=True, quiet=True)
        LOG.debug("[shutdown] Cleaning up resources ...")
        common.cleanup_resources()
        LOG.debug("[shutdown] Cleaning up Lambda resources ...")
        lambda_api.cleanup()

        if config.FORCE_SHUTDOWN:
            LOG.debug("[shutdown] Force shutdown, not waiting for infrastructure to shut down")
            return

        LOG.debug("[shutdown] Waiting for infrastructure to shut down ...")
        wait_for_infra_shutdown()
        LOG.debug("[shutdown] Infrastructure is shut down")
    finally:
        SHUTDOWN_INFRA.set()


def log_startup_message(service):
    print("Starting mock %s service on %s ..." % (service, edge_ports_info()))


def check_aws_credentials():
    session = boto3.Session()
    credentials = None
    # hardcode credentials here, to allow us to determine internal API calls made via boto3
    os.environ["AWS_ACCESS_KEY_ID"] = constants.INTERNAL_AWS_ACCESS_KEY_ID
    os.environ["AWS_SECRET_ACCESS_KEY"] = constants.INTERNAL_AWS_ACCESS_KEY_ID
    try:
        credentials = session.get_credentials()
    except Exception:
        pass
    session = boto3.Session()
    credentials = session.get_credentials()
    assert credentials


# -------------
# MAIN STARTUP
# -------------


def start_infra(asynchronous=False, apis=None):
    try:
        os.environ[LOCALSTACK_INFRA_PROCESS] = "1"

        is_in_docker = in_docker()
        # print a warning if we're not running in Docker but using Docker based LAMBDA_EXECUTOR
        if not is_in_docker and "docker" in config.LAMBDA_EXECUTOR and not is_linux():
            print(
                (
                    "!WARNING! - Running outside of Docker with $LAMBDA_EXECUTOR=%s can lead to "
                    "problems on your OS. The environment variable $LOCALSTACK_HOSTNAME may not "
                    "be properly set in your Lambdas."
                )
                % config.LAMBDA_EXECUTOR
            )

        if (
            is_in_docker
            and not config.LAMBDA_REMOTE_DOCKER
            and not os.environ.get("HOST_TMP_FOLDER")
        ):
            print(
                "!WARNING! - Looks like you have configured $LAMBDA_REMOTE_DOCKER=0 - "
                "please make sure to configure $HOST_TMP_FOLDER to point to your host's $TMPDIR"
            )

        print_version(is_in_docker)

        # apply patches
        patch_urllib3_connection_pool(maxsize=128)
        patch_instance_tracker_meta()

        # load plugins
        load_plugins()

        # with plugins loaded, now start the infrastructure
        thread = do_start_infra(asynchronous, apis, is_in_docker)

        if not asynchronous and thread:
            # We're making sure that we stay in the execution context of the
            # main thread, otherwise our signal handlers don't work
            SHUTDOWN_INFRA.wait()

        return thread

    except KeyboardInterrupt:
        print("Shutdown")
    except Exception as e:
        print("Error starting infrastructure: %s %s" % (e, traceback.format_exc()))
        sys.stdout.flush()
        raise e
    finally:
        if not asynchronous:
            stop_infra()


def do_start_infra(asynchronous, apis, is_in_docker):
    # import to avoid cyclic dependency
    from localstack.services.edge import BOOTSTRAP_LOCK

    event_publisher.fire_event(
        event_publisher.EVENT_START_INFRA,
        {"d": is_in_docker and 1 or 0, "c": in_ci() and 1 or 0},
    )

    # set up logging
    setup_logging()

    if config.DEVELOP:
        install.install_debugpy_and_dependencies()
        import debugpy

        LOG.info("Starting debug server at: %s:%s" % (constants.BIND_HOST, config.DEVELOP_PORT))
        debugpy.listen((constants.BIND_HOST, config.DEVELOP_PORT))

        if config.WAIT_FOR_DEBUGGER:
            debugpy.wait_for_client()

    # prepare APIs
    apis = canonicalize_api_names(apis)

    @log_duration()
    def prepare_environment():
        # set environment
        os.environ["AWS_REGION"] = config.DEFAULT_REGION
        os.environ["ENV"] = ENV_DEV
        # register signal handlers
        if not is_local_test_mode():
            register_signal_handlers()
        # make sure AWS credentials are configured, otherwise boto3 bails on us
        check_aws_credentials()

    @log_duration()
    def prepare_installation():
        # install libs if not present
        install.install_components(apis)

    @log_duration()
    def start_api_services():

        # Some services take a bit to come up
        sleep_time = 5
        # start services
        thread = None

        # loop through plugins and start each service
        for name, plugin in SERVICE_PLUGINS.items():
            if plugin.is_enabled(api_names=apis):
                record_service_health(name, "starting")
                t1 = plugin.start(asynchronous=True)
                thread = thread or t1

        time.sleep(sleep_time)
        # ensure that all infra components are up and running
        check_infra(apis=apis)
        # restore persisted data
        record_service_health(
            "features:persistence", "initializing" if config.DATA_DIR else "disabled"
        )
        persistence.restore_persisted_data(apis=apis)
        if config.DATA_DIR:
            record_service_health("features:persistence", "initialized")
        return thread

    prepare_environment()
    prepare_installation()
    with BOOTSTRAP_LOCK:
        thread = start_api_services()

        if config.DATA_DIR:
            persistence.save_startup_info()

    print(READY_MARKER_OUTPUT)
    sys.stdout.flush()

    INFRA_READY.set()

    return thread
