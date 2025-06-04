import threading

from localstack import config


class ThreadSafeCounter:
    """
    A thread-safe counter for any kind of tracking.
    This class should not be instantiated directly, use the 'Counter; factory instead.
    """

    _mutex: threading.Lock
    _count: int

    def __init__(self):
        super(ThreadSafeCounter, self).__init__()
        self._mutex = threading.Lock()
        self._count = 0

    @property
    def count(self) -> int:
        return self._count

    def increment(self, value: int = 1) -> None:
        """Increments the counter unless events are disabled."""
        if config.DISABLE_EVENTS:
            return

        if value <= 0:
            raise ValueError("Increment value must be positive.")

        with self._mutex:
            self._count += value

    def reset(self) -> None:
        """Resets the counter to zero unless events are disabled."""
        if config.DISABLE_EVENTS:
            return

        with self._mutex:
            self._count = 0
