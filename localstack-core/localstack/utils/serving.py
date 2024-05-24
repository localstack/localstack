import abc
import logging
import threading
from typing import Optional

from localstack.utils.net import is_port_open
from localstack.utils.sync import poll_condition
from localstack.utils.threads import FuncThread, start_thread

LOG = logging.getLogger(__name__)


class StopServer(Exception):
    pass


class Server(abc.ABC):
    """
    A Server implements the lifecycle of a server running in a thread.
    """

    def __init__(self, port: int, host: str = "localhost") -> None:
        super().__init__()
        self._thread: Optional[FuncThread] = None

        self._lifecycle_lock = threading.RLock()
        self._stopped = threading.Event()
        self._started = threading.Event()

        self._host = host
        self._port = port

    @property
    def host(self):
        return self._host

    @property
    def port(self):
        return self._port

    @property
    def protocol(self):
        return "http"

    @property
    def url(self):
        return "%s://%s:%s" % (self.protocol, self.host, self.port)

    def get_error(self) -> Optional[Exception]:
        """
        If the thread running the server returned with an Exception, then this function will return that exception.
        """
        if not self._started.is_set():
            return None

        future = self._thread.result_future
        if future.done():
            return future.exception()
        return None

    def wait_is_up(self, timeout: float = None) -> bool:
        """
        Waits until the server is started and is_up returns true.

        :param timeout: the time in seconds to wait before returning false. If timeout is None, then wait indefinitely.
        :returns: true if the server is up, false if not or the timeout was reached while waiting.
        """
        # first wait until the started event was called
        self._started.wait(timeout=timeout)
        # then poll the health check
        return poll_condition(self.is_up, timeout=timeout)

    def is_running(self) -> bool:
        """
        Checks whether the thread holding the server is running. The server may be running but not healthy (
        is_running == True, is_up == False).

        :returns: true if the server thread is running
        """
        if not self._started.is_set():
            return False
        if self._stopped.is_set():
            return False
        return self._thread.running

    def is_up(self) -> bool:
        """
        Checks whether the server is up by executing the health check function.

        :returns: false if the server has not been started or if the health check failed, true otherwise
        """
        if not self._started.is_set():
            return False

        try:
            return True if self.health() else False
        except Exception:
            return False

    def shutdown(self) -> None:
        """
        Attempts to shut down the server by calling the internal do_shutdown method. It only does this if the server
        has been started. Repeated calls to this function have no effect.

        :raises RuntimeError: shutdown was called before start
        """
        with self._lifecycle_lock:
            if not self._started.is_set():
                raise RuntimeError("cannot shutdown server before it is started")
            if self._stopped.is_set():
                return

            self._thread.stop()
            self._stopped.set()
            self.do_shutdown()

    def start(self) -> bool:
        """
        Starts the server by calling the internal do_run method in a new thread, and then returns True. Repeated
        calls to this function have no effect but return False.

        :return: True if the server was started in this call, False if the server was already started previously
        """
        with self._lifecycle_lock:
            if self._started.is_set():
                return False

            self._thread = self.do_start_thread()
            self._started.set()
            return True

    def join(self, timeout=None):
        """
        Waits for the given amount of time until the thread running the server returns. If the server hasn't started
        yet, it first waits for the server to start.

        :params: the time in seconds to wait. If None then wait indefinitely.
        :raises TimeoutError: If the server didn't shut down before the given timeout.
        """
        if not self._started.is_set():
            raise RuntimeError("cannot join server before it is started")

        if not self._started.wait(timeout):
            raise TimeoutError

        try:
            self._thread.result_future.result(timeout)
        except TimeoutError:
            raise
        except Exception:
            # Future.result() will re-raise the exception that was raised in the thread
            return

    def health(self):
        """
        Runs a health check on the server. The default implementation performs is_port_open on the server URL.
        """
        return is_port_open(self.url)

    def do_start_thread(self) -> FuncThread:
        """
        Creates and starts the thread running the server. By default, it calls the do_run method in a FuncThread, but
        can be overridden to if the subclass wants to return its own thread.
        """

        def _run(*_):
            try:
                return self.do_run()
            except StopServer:
                LOG.debug("stopping server %s", self.url)
            finally:
                self._stopped.set()

        return start_thread(_run, name=f"server-{self.__class__.__name__}")

    def do_run(self):
        """
        Runs the server (blocking method). (Needs to be overridden by subclasses of do_start_thread is not overridden).

        :raises StopServer: can be raised by the subclass to indicate the server should be stopped.
        """
        pass

    def do_shutdown(self):
        """
        Called when shutdown() is performed. (Should be overridden by subclasses).
        """
        pass
