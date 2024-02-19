import logging
import os
import signal
import sys
import threading
import traceback

from localstack import config, constants
from localstack.constants import AWS_REGION_US_EAST_1, LOCALSTACK_INFRA_PROCESS
from localstack.http.duplex_socket import enable_duplex_socket
from localstack.runtime import events, hooks
from localstack.runtime.exceptions import LocalstackExit
from localstack.services.plugins import SERVICE_PLUGINS, ServiceDisabled, wait_for_infra_shutdown
from localstack.utils import files, objects
from localstack.utils.analytics import usage
from localstack.utils.aws.request_context import patch_moto_request_handling
from localstack.utils.bootstrap import (
    get_enabled_apis,
    log_duration,
    setup_logging,
    should_eager_load_api,
)
from localstack.utils.container_networking import get_main_container_id
from localstack.utils.files import cleanup_tmp_files
from localstack.utils.net import is_port_open
from localstack.utils.patch import patch
from localstack.utils.platform import in_docker
from localstack.utils.sync import poll_condition
from localstack.utils.threads import (
    cleanup_threads_and_processes,
    start_thread,
)

# output string that indicates that the stack is ready
READY_MARKER_OUTPUT = constants.READY_MARKER_OUTPUT

# default backend host address
DEFAULT_BACKEND_HOST = "127.0.0.1"

# set up logger
LOG = logging.getLogger(__name__)

# event flag indicating the infrastructure has been started and that the ready marker has been printed
# TODO: deprecated, use events.infra_ready
INFRA_READY = events.infra_ready

# event flag indicating that the infrastructure has been shut down
SHUTDOWN_INFRA = threading.Event()

# can be set
EXIT_CODE: objects.Value[int] = objects.Value(0)


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
    from importlib.util import find_spec

    if not find_spec("moto"):
        return

    from moto.core.base_backend import InstanceTrackerMeta
    from moto.core.common_models import BaseModel

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


def exit_infra(code: int):
    """
    Triggers an orderly shutdown of the localstack infrastructure and sets the code the main process should
    exit with to a specific value.

    :param code: the exit code the main process should return with
    """
    EXIT_CODE.set(code)
    SHUTDOWN_INFRA.set()


def stop_infra():
    if events.infra_stopping.is_set():
        return

    usage.aggregate_and_send()

    # also used to signal shutdown for edge proxy so that any further requests will be rejected
    events.infra_stopping.set()

    try:
        LOG.debug("[shutdown] Running shutdown hooks ...")
        # run plugin hooks for infra shutdown
        hooks.on_infra_shutdown.run()

        LOG.debug("[shutdown] Cleaning up resources ...")
        cleanup_resources()

        if config.FORCE_SHUTDOWN:
            LOG.debug("[shutdown] Force shutdown, not waiting for infrastructure to shut down")
            return

        LOG.debug("[shutdown] Waiting for infrastructure to shut down ...")
        wait_for_infra_shutdown()
        LOG.debug("[shutdown] Infrastructure is shut down")
    finally:
        events.infra_stopped.set()


def cleanup_resources():
    cleanup_tmp_files()
    cleanup_threads_and_processes()

    if config.CLEAR_TMP_FOLDER:
        try:
            files.rm_rf(config.dirs.tmp)
        except PermissionError as e:
            LOG.error(
                "unable to delete temp folder %s: %s, please delete manually or you will keep seeing these errors",
                config.dirs.tmp,
                e,
            )
        try:
            files.rm_rf(config.dirs.mounted_tmp)
        except PermissionError as e:
            LOG.error(
                "unable to delete mounted temp folder %s: %s, please delete manually or you will keep seeing these errors",
                config.dirs.mounted_tmp,
                e,
            )


def gateway_listen_ports_info() -> str:
    """Example: http port [4566,443]"""
    gateway_listen_ports = [gw_listen.port for gw_listen in config.GATEWAY_LISTEN]
    return f"{config.get_protocol()} port {gateway_listen_ports}"


def log_startup_message(service):
    LOG.info("Starting mock %s service on %s ...", service, gateway_listen_ports_info())


def signal_supervisor_restart():
    if pid := os.environ.get("SUPERVISOR_PID"):
        os.kill(int(pid), signal.SIGUSR1)
    else:
        LOG.warning("could not signal supervisor to restart localstack")


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
    if config.CLEAR_TMP_FOLDER:
        # try to clear temp dir on startup
        try:
            files.rm_rf(config.dirs.tmp)
        except PermissionError as e:
            LOG.error(
                "unable to delete temp folder %s: %s, please delete manually or you will keep seeing these errors",
                config.dirs.tmp,
                e,
            )

    config.dirs.mkdirs()

    events.infra_starting.set()

    try:
        os.environ[LOCALSTACK_INFRA_PROCESS] = "1"

        is_in_docker = in_docker()

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
    except LocalstackExit as e:
        print(f"Localstack returning with exit code {e.code}. Reason: {e}")
        raise
    except Exception as e:
        print(
            "Unexpected exception while starting infrastructure: %s %s"
            % (e, traceback.format_exc())
        )
        raise e
    finally:
        sys.stdout.flush()
        if not asynchronous:
            stop_infra()


def do_start_infra(asynchronous, apis, is_in_docker):
    if config.DEVELOP:
        from localstack.packages.debugpy import debugpy_package

        debugpy_package.install()
        import debugpy

        LOG.info("Starting debug server at: %s:%s", constants.BIND_HOST, config.DEVELOP_PORT)
        debugpy.listen((constants.BIND_HOST, config.DEVELOP_PORT))

        if config.WAIT_FOR_DEBUGGER:
            debugpy.wait_for_client()

    @log_duration()
    def prepare_environment():
        # enable the HTTP/HTTPS duplex socket
        enable_duplex_socket()

        # set environment
        os.environ["AWS_REGION"] = AWS_REGION_US_EAST_1

        patch_moto_request_handling()

    @log_duration()
    def preload_services():
        """
        Preload services - restore persistence, and initialize services if EAGER_SERVICE_LOADING=1.
        """

        # listing the available service plugins will cause resolution of the entry points
        available_services = get_enabled_apis()

        # lazy is the default beginning with version 0.13.0
        if not config.EAGER_SERVICE_LOADING:
            return

        for api in available_services:
            if should_eager_load_api(api):
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
            lambda: is_port_open(config.GATEWAY_LISTEN[0].port), timeout=15, interval=0.3
        ):
            if LOG.isEnabledFor(logging.DEBUG):
                # make another call with quiet=False to print detailed error logs
                is_port_open(config.GATEWAY_LISTEN[0].port, quiet=False)
            raise TimeoutError(
                f"gave up waiting for edge server on {config.GATEWAY_LISTEN[0].host_and_port()}"
            )

        return t

    prepare_environment()
    thread = start_runtime_components()
    preload_services()

    print(READY_MARKER_OUTPUT)
    sys.stdout.flush()

    events.infra_ready.set()

    hooks.on_infra_ready.run()

    return thread
