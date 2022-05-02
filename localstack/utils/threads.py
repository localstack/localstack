import concurrent.futures
import inspect
import logging
import threading
import traceback
from concurrent.futures import Future
from multiprocessing.dummy import Pool
from typing import Callable, List

LOG = logging.getLogger(__name__)

# arrays for temporary threads and resources
TMP_THREADS = []
TMP_PROCESSES = []


class FuncThread(threading.Thread):
    """Helper class to run a Python function in a background thread."""

    def __init__(
        self, func, params=None, quiet=False, on_stop: Callable[["FuncThread"], None] = None
    ):
        threading.Thread.__init__(self)
        self.daemon = True
        self.params = params
        self.func = func
        self.quiet = quiet
        self.result_future = Future()
        self._stop_event = threading.Event()
        self.on_stop = on_stop

    def run(self):
        result = None
        try:
            kwargs = {}
            argspec = inspect.getfullargspec(self.func)
            if argspec.varkw or "_thread" in (argspec.args or []) + (argspec.kwonlyargs or []):
                kwargs["_thread"] = self
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
    def running(self):
        return not self._stop_event.is_set()

    def stop(self, quiet: bool = False) -> None:
        self._stop_event.set()

        if self.on_stop:
            try:
                self.on_stop(self)
            except Exception as e:
                LOG.warning("error while calling on_stop callback: %s", e)


def start_thread(method, *args, **kwargs) -> FuncThread:
    """Start the given method in a background thread, and add the thread to the TMP_THREADS shutdown hook"""
    _shutdown_hook = kwargs.pop("_shutdown_hook", True)
    thread = FuncThread(method, *args, **kwargs)
    thread.start()
    if _shutdown_hook:
        TMP_THREADS.append(thread)
    return thread


def start_worker_thread(method, *args, **kwargs):
    return start_thread(method, *args, _shutdown_hook=False, **kwargs)


def cleanup_threads_and_processes(quiet=True):
    from localstack.utils.run import kill_process_tree

    for thread in TMP_THREADS:
        if thread:
            try:
                # LOG.debug('[shutdown] Cleaning up thread: %s', thread)
                if hasattr(thread, "shutdown"):
                    thread.shutdown()
                    continue
                if hasattr(thread, "kill"):
                    thread.kill()
                    continue
                thread.stop(quiet=quiet)
            except Exception as e:
                print(e)
    for proc in TMP_PROCESSES:
        try:
            # LOG.debug('[shutdown] Cleaning up process: %s', proc)
            kill_process_tree(proc.pid)
            # proc.terminate()
        except Exception as e:
            print(e)
    # clean up async tasks
    try:
        import asyncio

        for task in asyncio.all_tasks():
            try:
                # LOG.debug('[shutdown] Canceling asyncio task: %s', task)
                task.cancel()
            except Exception as e:
                print(e)
    except Exception:
        pass
    LOG.debug("[shutdown] Done cleaning up threads / processes / tasks")
    # clear lists
    TMP_THREADS.clear()
    TMP_PROCESSES.clear()


def parallelize(func: Callable, arr: List, size: int = None):
    if not size:
        size = len(arr)
    if size <= 0:
        return None

    with Pool(size) as pool:
        return pool.map(func, arr)
