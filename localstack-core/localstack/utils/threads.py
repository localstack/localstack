import concurrent.futures
import logging
import subprocess
import threading
import traceback
from collections.abc import Callable
from concurrent.futures import Future
from multiprocessing.dummy import Pool
from typing import TYPE_CHECKING, Any, TypeVar

if TYPE_CHECKING:
    from typing_extensions import ParamSpec

    P = ParamSpec("P")

T = TypeVar("T")

LOG = logging.getLogger(__name__)

# arrays for temporary threads and resources
TMP_THREADS: list["FuncThread"] = []
TMP_PROCESSES: list[subprocess.Popen[Any]] = []

counter_lock = threading.Lock()
counter = 0


class FuncThread(threading.Thread):
    """Helper class to run a Python function in a background thread."""

    def __init__(
        self,
        func: "Callable[P, T]",
        params: Any = None,
        quiet: bool = False,
        on_stop: Callable[["FuncThread"], None] | None = None,
        name: str | None = None,
        daemon: bool = True,
    ):
        global counter
        global counter_lock

        if name:
            with counter_lock:
                counter += 1
                thread_counter_current = counter

            threading.Thread.__init__(
                self, name=f"{name}-functhread{thread_counter_current}", daemon=daemon
            )
        else:
            threading.Thread.__init__(self, daemon=daemon)

        self.params = params
        self.func = func
        self.quiet = quiet
        self.result_future: Future[T | Exception | None] = Future()
        self._stop_event = threading.Event()
        self.on_stop = on_stop

    def run(self) -> None:
        result: Any = None
        try:
            kwargs = {}  # type: ignore[var-annotated]
            result = self.func(self.params, **kwargs)
        except Exception as e:
            self.result_future.set_exception(e)
            result = e
            if not self.quiet:
                LOG.info(
                    "Thread run method %s(%s) failed: %s %s",
                    self.func,
                    self.params,
                    e,
                    traceback.format_exc(),
                )
        finally:
            try:
                self.result_future.set_result(result)
                pass
            except concurrent.futures.InvalidStateError as e:
                # this can happen on shutdown if the task is already canceled
                LOG.debug(e)

    @property
    def running(self) -> bool:
        return not self._stop_event.is_set()

    def stop(self, quiet: bool = False) -> None:
        self._stop_event.set()

        if self.on_stop:
            try:
                self.on_stop(self)
            except Exception as e:
                LOG.warning("error while calling on_stop callback: %s", e)


def start_thread(
    method: "Callable[P, T]",
    params: Any = None,
    quiet: bool = False,
    on_stop: Callable[["FuncThread"], None] | None = None,
    _shutdown_hook: bool = True,
    name: str | None = None,
) -> FuncThread:
    """Start the given method in a background thread, and add the thread to the TMP_THREADS shutdown hook"""
    if not name:
        # technically we should add a new level here for *internal* warnings
        LOG.debug("start_thread called without providing a custom name")
    name = name or method.__name__
    thread = FuncThread(method, params=params, quiet=quiet, name=name, on_stop=on_stop)
    thread.start()
    if _shutdown_hook:
        TMP_THREADS.append(thread)
    return thread


def start_worker_thread(
    method: "Callable[P, T]", params: Any = None, name: str | None = None
) -> FuncThread:
    return start_thread(method, params, _shutdown_hook=False, name=name or "start_worker_thread")


def cleanup_threads_and_processes(quiet: bool = True) -> None:
    from localstack.utils.run import kill_process_tree

    for thread in TMP_THREADS:
        if thread:
            try:
                if hasattr(thread, "shutdown"):
                    thread.shutdown()
                    continue
                if hasattr(thread, "kill"):
                    thread.kill()
                    continue
                thread.stop(quiet=quiet)
            except Exception as e:
                LOG.debug("[shutdown] Error stopping thread %s: %s", thread, e)
                if not thread.daemon:
                    LOG.warning(
                        "[shutdown] Non-daemon thread %s may block localstack shutdown", thread
                    )
    for proc in TMP_PROCESSES:
        try:
            kill_process_tree(proc.pid)
            # proc.terminate()
        except Exception as e:
            LOG.debug("[shutdown] Error cleaning up process tree %s: %s", proc, e)
    # clean up async tasks
    try:
        import asyncio

        for task in asyncio.all_tasks():
            try:
                task.cancel()
            except Exception as e:
                LOG.debug("[shutdown] Error cancelling asyncio task %s: %s", task, e)
    except Exception:
        pass
    LOG.debug("[shutdown] Done cleaning up threads / processes / tasks")
    # clear lists
    TMP_THREADS.clear()
    TMP_PROCESSES.clear()


def parallelize(func: Callable, arr: list, size: int = None):  # type: ignore
    if not size:
        size = len(arr)
    if size <= 0:
        return None

    with Pool(size) as pool:
        return pool.map(func, arr)
