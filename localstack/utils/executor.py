import itertools
import logging
import queue
import threading
import time
from concurrent.futures import Future, _base
from typing import Callable, NamedTuple, ParamSpec, TypeVar

LOG = logging.getLogger(__name__)

_P = ParamSpec("_P")
_T = TypeVar("_T")


class _WorkItem(NamedTuple):
    future: Future
    fn: Callable
    args: tuple
    kwargs: dict


_stop_work = _WorkItem(None, None, None, None)
"""Poison pill to stop workers."""


def _run_work_item(item: _WorkItem) -> None:
    """
    Invokes the function of the work item and either sets the future result or the exception.

    :param item: the work item to run
    """
    if not item.future.set_running_or_notify_cancel():
        return

    try:
        result = item.fn(*item.args, **item.kwargs)
    except BaseException as e:
        item.future.set_exception(e)
    else:
        item.future.set_result(result)


def _worker(executor: "DaemonThreadPool", work_queue: queue.Queue[_WorkItem]) -> None:
    """
    Event loop that is started within a worker thread to read work items from the shared work queue.
    :param executor: reference to the spawning executor
    :param work_queue: the work queue
    """
    try:
        while True:
            work_item = work_queue.get(block=True)

            if work_item is not _stop_work:
                _run_work_item(work_item)
                # Delete references to object. See issue16284
                del work_item

                # attempt to increment idle count
                executor._idle_semaphore.release()
                continue

            # Exit if:
            #   - The interpreter is shutting down OR
            #   - The executor that owns the worker has been collected OR
            #   - The executor that owns the worker has been shutdown.
            if executor._shutdown:
                # Flag the executor as shutting down as early as possible if it
                # is not gc-ed yet.
                if executor is not None:
                    executor._shutdown = True
                # Notice other workers
                work_queue.put(_stop_work)
                return

    except BaseException:
        LOG.exception("Exception in thread pool worker")


class DaemonThreadPool(_base.Executor):
    """
    Simple implementation of an Executor that spawns daemon threads. It is based on the default ThreadPoolExecutor
    implementation, but simplified significantly since we don't need to care about global shutdowns or reference
    keeping.
    """

    _counter = itertools.count().__next__

    def __init__(self, max_workers: int, thread_name_prefix: str = ""):
        self._max_workers = max_workers
        self._thread_name_prefix = thread_name_prefix or f"DaemonThreadPool-{self._counter()}"
        self._work_queue: queue.Queue[_WorkItem] = queue.Queue()
        self._idle_semaphore = threading.Semaphore(0)
        self._shutdown = False
        self._shutdown_lock = threading.Lock()
        self._threads: list[threading.Thread] = list()

    def submit(
        self,
        fn: Callable[_P, _T],
        /,
        *args: _P.args,
        **kwargs: _P.kwargs,
    ) -> Future[_T]:
        with self._shutdown_lock:
            if self._shutdown:
                raise RuntimeError("Cannot schedule submit jobs after shutdown")

            ftr = _base.Future()
            work = _WorkItem(ftr, fn, args, kwargs)

            self._work_queue.put(work)
            self._adjust_thread_count()
            return ftr

    def _adjust_thread_count(self) -> None:
        # if idle threads are available, don't spin new threads
        if self._idle_semaphore.acquire(timeout=0):
            return

        num_threads = len(self._threads)
        if num_threads >= self._max_workers:
            return

        thread_name = f"{self._thread_name_prefix}_{num_threads}"

        t = self._new_thread(name=thread_name, target=_worker, args=(self, self._work_queue))
        t.start()
        self._threads.append(t)

    def shutdown(
        self, wait: bool = True, *, cancel_futures: bool = False, timeout: float = None
    ) -> None:
        with self._shutdown_lock:
            self._shutdown = True
            if cancel_futures:
                # Drain all work items from the queue, and then cancel their
                # associated futures.
                while True:
                    try:
                        work_item = self._work_queue.get_nowait()
                    except queue.Empty:
                        break
                    if work_item is not None:
                        work_item.future.cancel()

            self._work_queue.put_nowait(_stop_work)
            self.join(timeout)

    def _new_thread(self, name: str, target: Callable, args: tuple) -> threading.Thread:
        return threading.Thread(
            target=target,
            name=name,
            args=args,
            daemon=True,
        )

    def join(self, timeout: float = None):
        """
        Wait for all worker threads to return.
        :param timeout: the max time to wait
        """
        if timeout:
            remaining = timeout
            for t in self._threads:
                then = time.time()
                t.join(timeout=remaining)
                remaining -= time.time() - then
                if remaining <= 0:
                    remaining = 0
        else:
            for t in self._threads:
                t.join()
