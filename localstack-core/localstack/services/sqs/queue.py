import time
from queue import Empty, PriorityQueue, Queue


class InterruptibleQueue[T](Queue):
    # is_shutdown is used to check whether we have triggered a shutdown of the Queue
    is_shutdown: bool

    def __init__(self, maxsize: int = 0):
        super().__init__(maxsize)
        self.is_shutdown = False

    def get(self, block: bool = True, timeout: float | None = None) -> T:
        with self.not_empty:
            if self.is_shutdown:
                raise Empty
            if not block:
                if not self._qsize():
                    raise Empty
            elif timeout is None:
                while not self._qsize() and not self.is_shutdown:  # additional shutdown check
                    self.not_empty.wait()
            elif timeout < 0:
                raise ValueError("'timeout' must be a non-negative number")
            else:
                endtime = time.time() + timeout
                while not self._qsize() and not self.is_shutdown:  # additional shutdown check
                    remaining = endtime - time.time()
                    if remaining <= 0.0:
                        raise Empty
                    self.not_empty.wait(remaining)
            if self.is_shutdown:  # additional shutdown check
                raise Empty
            item = self._get()
            self.not_full.notify()
            return item

    def shutdown(self) -> None:
        """
        `shutdown` signals to stop all current and future `Queue.get` calls from executing.

        This is helpful for exiting otherwise blocking calls early.
        """
        with self.not_empty:
            self.is_shutdown = True
            self.not_empty.notify_all()


class InterruptiblePriorityQueue[T](PriorityQueue[T], InterruptibleQueue[T]):
    pass
