import logging
import os
import threading

from plux import PluginManager

from localstack import config, constants
from localstack.runtime import events, hooks
from localstack.utils import files, net, sync, threads

from .components import Components

LOG = logging.getLogger(__name__)


class LocalstackRuntime:
    """
    The localstack runtime. It has the following responsibilities:

      - Manage localstack filesystem directories
      - Execute runtime lifecycle hook plugins from ``localstack.runtime.hooks``.
      - Manage the localstack SSL certificate
      - Serve the gateway (It uses a ``RuntimeServer`` to serve a ``Gateway`` instance coming from the
        ``Components`` factory.)
    """

    def __init__(self, components: Components):
        self.components = components

        # at some point, far far in the future, we should no longer access a global config object, but rather
        # the one from the current runtime. This will allow us to truly instantiate multiple localstack
        # runtime instances in one process, which can be useful for many different things. but there is too
        # much global state at the moment think about this seriously. however, this assignment here can
        # serve as a reminder to avoid global state in general.
        self.config = config

        # TODO: move away from `localstack.runtime.events` and instantiate new `threading.Event()` here
        #  instead
        self.starting = events.infra_starting
        self.ready = events.infra_ready
        self.stopping = events.infra_stopping
        self.stopped = events.infra_stopped

    def run(self):
        """
        Start the main control loop of the runtime and block the thread. This will initialize the
        filesystem, run all lifecycle hooks, initialize the gateway server, and then serve the
        ``RuntimeServer`` until ``shutdown()`` is called.
        """
        # indicates to the environment that this is an "infra process" (old terminology referring to the
        # localstack runtime). this is necessary for disabling certain hooks that may run in the context of
        # the CLI host mode. TODO: should not be needed over time.
        os.environ[constants.LOCALSTACK_INFRA_PROCESS] = "1"

        self._init_filesystem()
        self._on_starting()
        self._init_gateway_server()

        # since we are blocking the main thread with the runtime server, we need to run the monitor that
        # prints the ready marker asynchronously. this is different from how the runtime was started in the
        # past, where the server was running in a thread.
        # TODO: ideally we pass down a `shutdown` event that can be waited on so we can cancel the thread
        #  if the runtime shuts down beforehand
        threading.Thread(target=self._run_ready_monitor, daemon=True).start()
        # FIXME: legacy compatibility code
        threading.Thread(target=self._run_shutdown_monitor, daemon=True).start()

        # run the main control loop of the server and block execution
        try:
            self.components.runtime_server.run()
        finally:
            self._on_return()

    def exit(self, code: int = 0):
        """
        Sets the exit code and runs ``shutdown``. It does not actually call ``sys.exit``, this is for the
        caller to do.

        :param code: the exit code to be set
        """
        self.exit_code = code
        # we don't know yet why, but shutdown does not work on the main thread
        threading.Thread(target=self.shutdown, name="Runtime-Shutdown").start()

    def shutdown(self):
        """
        Initiates an orderly shutdown of the runtime by stopping the main control loop of the
        ``RuntimeServer``. The shutdown hooks are actually called by the main control loop (in the main
        thread) after it returns.
        """
        if self.stopping.is_set():
            return
        self.stopping.set()
        self.components.runtime_server.shutdown()

    def is_ready(self) -> bool:
        return self.ready.is_set()

    def _init_filesystem(self):
        self._clear_tmp_directory()
        self.config.dirs.mkdirs()

    def _init_gateway_server(self):
        from localstack.utils.ssl import create_ssl_cert, install_predefined_cert_if_available

        install_predefined_cert_if_available()
        serial_number = self.config.GATEWAY_LISTEN[0].port
        _, cert_file_name, key_file_name = create_ssl_cert(serial_number=serial_number)
        ssl_creds = (cert_file_name, key_file_name)

        self.components.runtime_server.register(
            self.components.gateway, self.config.GATEWAY_LISTEN, ssl_creds
        )

    def _on_starting(self):
        self.starting.set()
        hooks.on_runtime_start.run()

    def _on_ready(self):
        hooks.on_runtime_ready.run()
        print(constants.READY_MARKER_OUTPUT, flush=True)
        self.ready.set()

    def _on_return(self):
        LOG.debug("[shutdown] Running shutdown hooks ...")
        hooks.on_runtime_shutdown.run()
        LOG.debug("[shutdown] Cleaning up resources ...")
        self._cleanup_resources()
        self.stopped.set()
        LOG.debug("[shutdown] Completed, bye!")

    def _run_ready_monitor(self):
        self._wait_for_gateway()
        self._on_ready()

    def _wait_for_gateway(self):
        host_and_port = self.config.GATEWAY_LISTEN[0]

        if not sync.poll_condition(
            lambda: net.is_port_open(host_and_port.port), timeout=15, interval=0.3
        ):
            if LOG.isEnabledFor(logging.DEBUG):
                # make another call with quiet=False to print detailed error logs
                net.is_port_open(host_and_port.port, quiet=False)
            raise TimeoutError(f"gave up waiting for gateway server to start on {host_and_port}")

    def _clear_tmp_directory(self):
        if self.config.CLEAR_TMP_FOLDER:
            # try to clear temp dir on startup
            try:
                files.rm_rf(self.config.dirs.tmp)
            except PermissionError as e:
                LOG.error(
                    "unable to delete temp folder %s: %s, please delete manually or you will "
                    "keep seeing these errors.",
                    self.config.dirs.tmp,
                    e,
                )

    def _cleanup_resources(self):
        threads.cleanup_threads_and_processes()
        self._clear_tmp_directory()

    # more legacy compatibility code
    @property
    def exit_code(self):
        # FIXME: legacy compatibility code
        from localstack.runtime import legacy

        return legacy.EXIT_CODE.get()

    @exit_code.setter
    def exit_code(self, value):
        # FIXME: legacy compatibility code
        from localstack.runtime import legacy

        legacy.EXIT_CODE.set(value)

    def _run_shutdown_monitor(self):
        # FIXME: legacy compatibility code. this can be removed once we replace access to the
        #  ``SHUTDOWN_INFRA`` event with ``get_current_runtime().shutdown()``.
        from localstack.runtime import legacy

        legacy.SHUTDOWN_INFRA.wait()
        self.shutdown()


def create_from_environment() -> LocalstackRuntime:
    """
    Creates a new runtime instance from the current environment. It uses a plugin manager to resolve the
    necessary components from the ``localstack.runtime.components`` plugin namespace to start the runtime.

    TODO: perhaps we could control which components should be instantiated with a config variable/constant

    :return: a new LocalstackRuntime instance
    """
    hooks.on_runtime_create.run()

    plugin_manager = PluginManager(Components.namespace)
    components = plugin_manager.load_all()

    if not components:
        raise ValueError(
            f"No component plugins found in namespace {Components.namespace}. Are entry points created "
            f"correctly?"
        )

    if len(components) > 1:
        LOG.warning(
            "There are more than one component plugins, using the first one which is %s",
            components[0].name,
        )

    return LocalstackRuntime(components[0])
