import logging
import os
import re
import signal
import subprocess
import sys
import threading
import traceback
from typing import Dict, List, Union

import boto3
from localstack_client.config import get_service_port
from moto.core import BaseModel
from moto.core.models import InstanceTrackerMeta

from localstack import config, constants
from localstack.constants import ENV_DEV, LOCALSTACK_INFRA_PROCESS, LOCALSTACK_VENV_FOLDER
from localstack.runtime import hooks
from localstack.services import generic_proxy, install, motoserver
from localstack.services.generic_proxy import ProxyListener, start_proxy_server
from localstack.services.plugins import SERVICE_PLUGINS, ServiceDisabled, wait_for_infra_shutdown
from localstack.utils import analytics, common, config_listener, persistence
from localstack.utils.analytics import event_publisher
from localstack.utils.aws.request_context import patch_moto_request_handling
from localstack.utils.bootstrap import (
    canonicalize_api_names,
    get_main_container_id,
    in_ci,
    log_duration,
    setup_logging,
)
from localstack.utils.common import (
    TMP_THREADS,
    ShellCommandThread,
    get_free_tcp_port,
    in_docker,
    is_linux,
    is_port_open,
    poll_condition,
    run,
    start_thread,
)
from localstack.utils.files import cleanup_tmp_files
from localstack.utils.patch import patch
from localstack.utils.run import FuncThread
from localstack.utils.server import multiserver
from localstack.utils.testutil import is_local_test_mode
from localstack.utils.threads import cleanup_threads_and_processes

# flag to indicate whether signal handlers have been set up already
SIGNAL_HANDLERS_SETUP = False

# output string that indicates that the stack is ready
READY_MARKER_OUTPUT = constants.READY_MARKER_OUTPUT

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
    """Avoid instance collection for moto dashboard"""

    if hasattr(InstanceTrackerMeta, "_ls_patch_applied"):
        return  # ensure we're not applying the patch multiple times

    @patch(InstanceTrackerMeta.__new__, pass_target=False)
    def new_instance(meta, name, bases, dct):
        cls = super(InstanceTrackerMeta, meta).__new__(meta, name, bases, dct)
        if name == "BaseModel":
            return cls
        cls.instances = []
        return cls

    @patch(BaseModel.__new__, pass_target=False)
    def new_basemodel(cls, *args, **kwargs):
        # skip cls.instances.append(..) which is done by the original/upstream constructor
        instance = super(BaseModel, cls).__new__(cls)
        return instance

    InstanceTrackerMeta._ls_patch_applied = True


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


def do_run(
    cmd: Union[str, List],
    asynchronous: bool,
    print_output: bool = None,
    env_vars: Dict[str, str] = None,
    auto_restart=False,
    strip_color: bool = False,
):
    sys.stdout.flush()
    if asynchronous:
        if config.DEBUG and print_output is None:
            print_output = True
        outfile = subprocess.PIPE if print_output else None
        t = ShellCommandThread(
            cmd,
            outfile=outfile,
            env_vars=env_vars,
            auto_restart=auto_restart,
            strip_color=strip_color,
        )
        t.start()
        TMP_THREADS.append(t)
        return t
    return run(cmd, env_vars=env_vars)


class MotoServerProperties:
    moto_thread: FuncThread
    service_port: int

    def __init__(self, moto_thread: FuncThread, service_port: int):
        self.moto_thread = moto_thread
        self.service_port = service_port


def start_proxy_for_service(
    service_name, port, backend_port, update_listener, quiet=False, params=None
):
    if params is None:
        params = {}
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


def start_proxy(
    port: int,
    backend_url: str = None,
    update_listener=None,
    quiet: bool = False,
    params: Dict = None,
    use_ssl: bool = None,
):
    use_ssl = config.USE_SSL if use_ssl is None else use_ssl
    params = {} if params is None else params
    proxy_thread = start_proxy_server(
        port=port,
        forward_url=backend_url,
        use_ssl=use_ssl,
        update_listener=update_listener,
        quiet=quiet,
        params=params,
        check_port=False,
    )
    return proxy_thread


def start_moto_server(
    key, port, name=None, backend_port=None, asynchronous=False, update_listener=None
) -> MotoServerProperties:
    # TODO: refactor this method! the name and parameters suggest that a server is started, but it actually only adds
    #  a proxy listener around the already started motoserver singleton.
    # TODO: remove asynchronous parameter (from all calls to this function)
    # TODO: re-think backend_port parameter (still needed since determined by motoserver singleton?)

    if not name:
        name = key
    log_startup_message(name)
    if not backend_port:
        if config.FORWARD_EDGE_INMEM:
            backend_port = motoserver.get_moto_server().port
        elif config.USE_SSL or update_listener:
            backend_port = get_free_tcp_port()
    if backend_port or config.FORWARD_EDGE_INMEM:
        start_proxy_for_service(key, port, backend_port, update_listener)

    server = motoserver.get_moto_server()
    return MotoServerProperties(server._thread, server.port)


def start_moto_server_separate(key, port, name=None, backend_port=None, asynchronous=False):
    moto_server_cmd = "%s/bin/moto_server" % LOCALSTACK_VENV_FOLDER
    if not os.path.exists(moto_server_cmd):
        moto_server_cmd = run("which moto_server").strip()
    server_port = backend_port or port
    cmd = "VALIDATE_LAMBDA_S3=0 %s %s -p %s -H %s" % (
        moto_server_cmd,
        key,
        server_port,
        constants.BIND_HOST,
    )
    return MotoServerProperties(do_run(cmd, asynchronous), server_port)


def add_service_proxy_listener(api: str, listener: ProxyListener, port=None):
    PROXY_LISTENERS[api] = (api, port or get_service_port(api), listener)


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
    # also used to signal shutdown for edge proxy so that any further requests will be rejected
    common.INFRA_STOPPED = True  # TODO: should probably be STOPPING since it isn't stopped yet

    event_publisher.fire_event(event_publisher.EVENT_STOP_INFRA)
    analytics.log.event("infra_stop")

    try:
        generic_proxy.QUIET = True  # TODO: this doesn't seem to be doing anything
        LOG.debug("[shutdown] Cleaning up services ...")
        SERVICE_PLUGINS.stop_all_services()
        LOG.debug("[shutdown] Cleaning up resources ...")
        cleanup_resources()

        if config.FORCE_SHUTDOWN:
            LOG.debug("[shutdown] Force shutdown, not waiting for infrastructure to shut down")
            return

        LOG.debug("[shutdown] Waiting for infrastructure to shut down ...")
        wait_for_infra_shutdown()
        LOG.debug("[shutdown] Infrastructure is shut down")
    finally:
        SHUTDOWN_INFRA.set()


def cleanup_resources():
    cleanup_tmp_files()
    cleanup_threads_and_processes()


def log_startup_message(service):
    LOG.info("Starting mock %s service on %s ...", service, config.edge_ports_info())


def check_aws_credentials():
    session = boto3.Session()
    credentials = None
    # hardcode credentials here, to allow us to determine internal API calls made via boto3
    os.environ["AWS_ACCESS_KEY_ID"] = constants.INTERNAL_AWS_ACCESS_KEY_ID
    os.environ["AWS_SECRET_ACCESS_KEY"] = constants.INTERNAL_AWS_SECRET_ACCESS_KEY
    try:
        credentials = session.get_credentials()
    except Exception:
        pass
    session = boto3.Session()
    credentials = session.get_credentials()
    assert credentials


def terminate_all_processes_in_docker():
    if not in_docker():
        # make sure we only run this inside docker!
        return
    print("INFO: Received command to restart all processes ...")
    cmd = (
        'ps aux | grep -v supervisor | grep -v docker-entrypoint.sh | grep -v "bin/localstack" | '
        "grep -v localstack_infra.log | awk '{print $1}' | grep -v PID"
    )
    pids = run(cmd).strip()
    pids = re.split(r"\s+", pids)
    pids = [int(pid) for pid in pids]
    this_pid = os.getpid()
    for pid in pids:
        if pid != this_pid:
            try:
                # kill spawned process
                os.kill(pid, signal.SIGKILL)
            except Exception:
                pass
    # kill the process itself
    sys.exit(0)


# -------------
# MAIN STARTUP
# -------------


def print_runtime_information(in_docker=False):
    # FIXME: this is legacy code from the old CLI, reconcile with new CLI and runtime output

    print()
    print("LocalStack version: %s" % constants.VERSION)
    if in_docker:
        id = get_main_container_id()
        if id:
            print("LocalStack Docker container id: %s" % id[:12])

    if config.LOCALSTACK_BUILD_DATE:
        print("LocalStack build date: %s" % config.LOCALSTACK_BUILD_DATE)

    if config.LOCALSTACK_BUILD_GIT_HASH:
        print("LocalStack build git hash: %s" % config.LOCALSTACK_BUILD_GIT_HASH)

    print()


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

        if is_in_docker and not config.LAMBDA_REMOTE_DOCKER and not config.dirs.functions:
            print(
                "!WARNING! - Looks like you have configured $LAMBDA_REMOTE_DOCKER=0 - "
                "please make sure to configure $HOST_TMP_FOLDER to point to your host's $TMPDIR"
            )

        print_runtime_information(is_in_docker)

        # apply patches
        patch_urllib3_connection_pool(maxsize=128)
        patch_instance_tracker_meta()

        # set up logging
        setup_logging()

        # run hooks, to allow them to apply patches and changes
        hooks.on_infra_start.run()
        # with changes that hooks have made, now start the infrastructure
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

    event_publisher.fire_event(
        event_publisher.EVENT_START_INFRA,
        {"d": is_in_docker and 1 or 0, "c": in_ci() and 1 or 0},
    )

    if config.DEVELOP:
        install.install_debugpy_and_dependencies()
        import debugpy

        LOG.info("Starting debug server at: %s:%s", constants.BIND_HOST, config.DEVELOP_PORT)
        debugpy.listen((constants.BIND_HOST, config.DEVELOP_PORT))

        if config.WAIT_FOR_DEBUGGER:
            debugpy.wait_for_client()

    # prepare APIs
    apis = canonicalize_api_names(apis)
    analytics.log.event("infra_start", apis=apis)

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
        patch_moto_request_handling()

    @log_duration()
    def prepare_installation():
        # install libs if not present
        install.install_components(apis)

    @log_duration()
    def preload_services():
        """
        Preload services - restore persistence, and initialize services if EAGER_SERVICE_LOADING=1.
        """

        # listing the available service plugins will cause resolution of the entry points
        available_services = SERVICE_PLUGINS.list_available()

        if persistence.is_persistence_enabled():
            if not config.is_env_true(constants.ENV_PRO_ACTIVATED):
                LOG.warning(
                    "Persistence mechanism for community services (based on API calls record&replay) "
                    "will be deprecated in versions 0.13.0 and above"
                )

            persistence.restore_persisted_data(available_services)

        # lazy is the default beginning with version 0.13.0
        if not config.EAGER_SERVICE_LOADING:
            return

        for api in available_services:
            try:
                SERVICE_PLUGINS.require(api)
            except ServiceDisabled as e:
                LOG.debug("%s", e)
            except Exception:
                LOG.exception("could not load service plugin %s", api)

    @log_duration()
    def start_runtime_components():
        from localstack.services.edge import start_edge

        # TODO: we want a composable LocalStack runtime (edge proxy, service manager, dns, ...)
        t = start_thread(start_edge, quiet=False)

        # TODO: properly encapsulate starting/stopping of edge server in a class
        if not poll_condition(
            lambda: is_port_open(config.get_edge_port_http()), timeout=15, interval=0.3
        ):
            if LOG.isEnabledFor(logging.DEBUG):
                # make another call with quiet=False to print detailed error logs
                is_port_open(config.get_edge_port_http(), quiet=False)
            raise TimeoutError(
                f"gave up waiting for edge server on {config.EDGE_BIND_HOST}:{config.EDGE_PORT}"
            )

        return t

    prepare_environment()
    prepare_installation()
    thread = start_runtime_components()
    preload_services()

    if config.dirs.data:
        persistence.save_startup_info()

    print(READY_MARKER_OUTPUT)
    sys.stdout.flush()

    INFRA_READY.set()
    analytics.log.event("infra_ready")

    hooks.on_infra_ready.run()

    return thread
