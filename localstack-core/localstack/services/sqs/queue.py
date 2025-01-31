import threading
import time
from queue import Empty, PriorityQueue, Queue


class InterruptibleQueue(Queue):
    shutdown_event: threading.Event

    def __init__(self, maxsize=0):
        super().__init__(maxsize)
        self.shutdown_event = threading.Event()

    def get(self, block=True, timeout=None):
        with self.not_empty:
            if not block:
                if not self._qsize():
                    raise Empty
            elif timeout is None:
                while not self._qsize() and not self.shutdown_event.is_set():
                    self.not_empty.wait()
            elif timeout < 0:
                raise ValueError("'timeout' must be a non-negative number")
            else:
                endtime = time.time() + timeout
                while not self._qsize() and not self.shutdown_event.is_set():
                    remaining = endtime - time.time()
                    if remaining <= 0.0:
                        raise Empty
                    self.not_empty.wait(remaining)
            if self.shutdown_event.is_set():
                raise Empty
            item = self._get()
            self.not_full.notify()
            return item

    def shutdown(self):
        self.shutdown_event.set()
        with self.not_empty:
            self.not_empty.notify_all()


class InterruptiblePriorityQueue(PriorityQueue, InterruptibleQueue):
    pass
