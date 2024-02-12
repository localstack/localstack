import abc
import logging
import threading
from typing import Generic, TypeVar

LOG = logging.getLogger(__name__)


class StoppableThread(threading.Thread, abc.ABC):
    @abc.abstractmethod
    def stop(self):
        pass


T = TypeVar("T", bound=StoppableThread)


class ThreadScaler(Generic[T], abc.ABC):
    running_threads: list[T]
    stopping_threads: list[T]
    scaling_lock: threading.RLock
    stopping_lock: threading.RLock
    max_timeout: int

    def __init__(self):
        self.running_threads = []
        self.stopping_threads = []
        self.scaling_lock = threading.RLock()
        self.stopping_lock = threading.RLock()
        self.max_timeout = 3

    @abc.abstractmethod
    def create_thread(self) -> T:
        pass

    def start_thread(self) -> None:
        thread = self.create_thread()
        self.running_threads.append(thread)
        thread.start()

    def scale_to(self, instances: int) -> None:
        """
        Scales up / down to leave only the chosen number of instances running.
        :param instances: Positive integer value of running instances to achieve
        """
        LOG.debug("Scaling to %s threads", instances)
        with self.scaling_lock:
            running_instances = len(self.running_threads)
            if running_instances < instances:
                for _ in range(instances - running_instances):
                    self.start_thread()
            elif running_instances > instances:
                for _ in range(running_instances - instances):
                    thread = self.choose_stopping_thread()
                    self._stop_thread(thread)

    def choose_stopping_thread(self) -> T:
        return self.running_threads.pop()

    def running_workers(self) -> int:
        return len(self.running_threads)

    def _stop_thread(self, thread: T) -> None:
        """
        Stops a thread
        """
        self.stopping_threads.append(thread)
        thread.stop()

    def stop(self) -> None:
        with self.stopping_lock:
            for thread in list(self.running_threads):
                self.running_threads.remove(thread)
                self._stop_thread(thread)

    def wait_for_stopped_threads(self) -> bool:
        """
        Joins all the stopped threads and removes them from the list of stopping threads if they joined correctly
        :return True if all the stopped threads were joined, False if some of the thread joins timed out
        """
        # lock to avoid multiple concurrent calls interfering
        with self.stopping_lock:
            for thread in list(self.stopping_threads):
                thread.join(timeout=self.max_timeout)
                if not thread.is_alive():
                    self.stopping_threads.remove(thread)
            return not self.stopping_threads

    def has_stopping_threads(self) -> bool:
        return bool(self.stopping_threads)
