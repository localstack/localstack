import itertools
import logging
import os
import queue
import threading

LOG = logging.getLogger(__name__)


def _worker(work_queue: queue.Queue):
    try:
        while True:
            work_item = work_queue.get(block=True)
            if work_item is None:
                return
            work_item.run()
            # delete reference to the work item to avoid it being in memory until the next blocking `queue.get` call returns
            del work_item

    except Exception:
        LOG.exception("Exception in worker")


class _WorkItem:
    def __init__(self, fn, args, kwargs):
        self.fn = fn
        self.args = args
        self.kwargs = kwargs

    def run(self):
        try:
            self.fn(*self.args, **self.kwargs)
        except Exception:
            LOG.exception("Unhandled Exception in while running %s", self.fn.__name__)


class TopicPartitionedThreadPoolExecutor:
    """
    This topic partition the work between workers based on Topics.
    It guarantees that each Topic only has one worker assigned, and thus that the tasks will be executed sequentially.

    Loosely based on ThreadPoolExecutor for stdlib, but does not return Future as SNS does not need it (fire&forget)
    Could be extended if needed to fit other needs.

    Currently, we do not re-balance between workers if some of them have more load. This could be investigated.
    """

    # Used to assign unique thread names when thread_name_prefix is not supplied.
    _counter = itertools.count().__next__

    def __init__(self, max_workers: int = None, thread_name_prefix: str = ""):
        if max_workers is None:
            max_workers = min(32, (os.cpu_count() or 1) + 4)
        if max_workers <= 0:
            raise ValueError("max_workers must be greater than 0")

        self._max_workers = max_workers
        self._thread_name_prefix = (
            thread_name_prefix or f"TopicThreadPoolExecutor-{self._counter()}"
        )

        # for now, the pool isn't fair and is not redistributed depending on load
        self._pool = {}
        self._shutdown = False
        self._lock = threading.Lock()
        self._threads = set()
        self._work_queues = []
        self._cycle = itertools.cycle(range(max_workers))

    def _add_worker(self):
        work_queue = queue.SimpleQueue()
        self._work_queues.append(work_queue)
        thread_name = f"{self._thread_name_prefix}_{len(self._threads)}"
        t = threading.Thread(name=thread_name, target=_worker, args=(work_queue,))
        t.daemon = True
        t.start()
        self._threads.add(t)

    def _get_work_queue(self, topic: str) -> queue.SimpleQueue:
        if not (work_queue := self._pool.get(topic)):
            if len(self._threads) < self._max_workers:
                self._add_worker()

            # we cycle through the possible indexes for a work queue, in order to distribute the load across
            # once we get to the max amount of worker, the cycle will start back at 0
            index = next(self._cycle)
            work_queue = self._work_queues[index]

            # TODO: the pool is not cleaned up at the moment, think about the clean-up interface
            self._pool[topic] = work_queue
        return work_queue

    def submit(self, fn, topic, /, *args, **kwargs) -> None:
        with self._lock:
            work_queue = self._get_work_queue(topic)

            if self._shutdown:
                raise RuntimeError("cannot schedule new futures after shutdown")

            w = _WorkItem(fn, args, kwargs)
            work_queue.put(w)

    def shutdown(self, wait=True):
        with self._lock:
            self._shutdown = True

            # Send a wake-up to prevent threads calling
            # _work_queue.get(block=True) from permanently blocking.
            for work_queue in self._work_queues:
                work_queue.put(None)

        if wait:
            for t in self._threads:
                t.join()
