import copy
import logging
import threading
import time
from typing import Generic, Protocol, TypeVar, overload

LOG = logging.getLogger(__name__)

T = TypeVar("T")

# alias to signify whether a batch policy has been triggered
BatchPolicyTriggered = bool


# TODO: Add batching on bytes as well.
class Batcher(Generic[T]):
    """
    A utility for collecting items into batches and flushing them when one or more batch policy conditions are met.

    The batch policy can be created to trigger on:
    - max_count: Maximum number of items added
    - max_window: Maximum time window (in seconds)

    If no limits are specified, the batcher is always in triggered state.

    Example usage:

        import time

        # Triggers when 2 (or more) items are added
        batcher = Batcher(max_count=2)
        assert batcher.add(["item1", "item2", "item3"])
        assert batcher.flush() == ["item1", "item2", "item3"]

        # Triggers partially when 2 (or more) items are added
        batcher = Batcher(max_count=2)
        assert batcher.add(["item1", "item2", "item3"])
        assert batcher.flush(partial=True) == ["item1", "item2"]
        assert batcher.add("item4")
        assert batcher.flush(partial=True) == ["item3", "item4"]

        # Trigger 2 seconds after the first add
        batcher = Batcher(max_window=2.0)
        assert not batcher.add(["item1", "item2", "item3"])
        time.sleep(2.1)
        assert not batcher.add(["item4"])
        assert batcher.flush() == ["item1", "item2", "item3", "item4"]
    """

    max_count: int | None
    """
    Maximum number of items, must be None or positive.
    """

    max_window: float | None
    """
    Maximum time window in seconds, must be None or positive.
    """

    _triggered: bool
    _last_batch_time: float
    _batch: list[T]

    def __init__(self, max_count: int | None = None, max_window: float | None = None):
        """
        Initialize a new Batcher instance.

        :param max_count: Maximum number of items that be None or positive.
        :param max_window: Maximum time window in seconds that must be None or positive.
        """
        self.max_count = max_count
        self.max_window = max_window

        self._triggered = False
        self._last_batch_time = time.monotonic()
        self._batch = []

    @property
    def period(self) -> float:
        return time.monotonic() - self._last_batch_time

    def _check_batch_policy(self) -> bool:
        """Check if any batch policy conditions are met"""
        if self.max_count is not None and len(self._batch) >= self.max_count:
            self._triggered = True
        elif self.max_window is not None and self.period >= self.max_window:
            self._triggered = True
        elif not self.max_count and not self.max_window:
            # always return true
            self._triggered = True

        return self._triggered

    @overload
    def add(self, item: T, *, deep_copy: bool = False) -> BatchPolicyTriggered: ...

    @overload
    def add(self, items: list[T], *, deep_copy: bool = False) -> BatchPolicyTriggered: ...

    def add(self, item_or_items: T | list[T], *, deep_copy: bool = False) -> BatchPolicyTriggered:
        """
        Add an item or list of items to the collected batch.

        Returns:
            BatchPolicyTriggered: True if the batch policy was triggered during addition, False otherwise.
        """
        if deep_copy:
            item_or_items = copy.deepcopy(item_or_items)

        if isinstance(item_or_items, list):
            self._batch.extend(item_or_items)
        else:
            self._batch.append(item_or_items)

        # Check if the last addition triggered the batch policy
        return self.is_triggered()

    def flush(self, *, partial=False) -> list[T]:
        result = []
        if not partial or not self.max_count:
            result = self._batch.copy()
            self._batch.clear()
        else:
            batch_size = min(self.max_count, len(self._batch))
            result = self._batch[:batch_size].copy()
            self._batch = self._batch[batch_size:]

        self._last_batch_time = time.monotonic()
        self._triggered = False
        self._check_batch_policy()

        return result

    def duration_until_next_batch(self) -> float:
        if not self.max_window:
            return -1
        return max(self.max_window - self.period, -1)

    def get_current_size(self) -> int:
        return len(self._batch)

    def is_triggered(self):
        return self._triggered or self._check_batch_policy()


class BatchHandler(Protocol[T]):
    """
    A BatchHandler is a callable that processes a list of items handed down by the AsyncBatcher.
    """

    def __call__(self, batch: list[T]) -> None: ...


class AsyncBatcher(Generic[T]):
    """
    Class for managing asynchronous batching of items.

    This class allows for efficient buffering and processing of items in batches by
    periodically flushing the buffer to a given handler, or by automatically flushing
    when the maximum batch size is reached. It is designed to be used in asynchronous
    scenarios where the caller does not execute the flushing IO call itself, like with ``Batcher``.

    :ivar max_flush_interval: Maximum time interval in seconds between
        automatic flushes, regardless of the batch size.
    :ivar max_batch_size: Maximum number of items in a batch. When reached,
        the batch is flushed automatically.
    :ivar handler: Callable handler that processes each flushed batch. The handler must
        be provided during initialization and must accept a list of items as input.
    """

    max_flush_interval: float
    max_batch_size: int
    handler: BatchHandler[T]

    _buffer: list[T]
    _flush_lock: threading.Condition
    _closed: bool

    def __init__(
        self,
        handler: BatchHandler[T],
        max_flush_interval: float = 10,
        max_batch_size: int = 20,
    ):
        self.handler = handler
        self.max_flush_interval = max_flush_interval
        self.max_batch_size = max_batch_size

        self._buffer = []
        self._flush_lock = threading.Condition()
        self._closed = False

    def add(self, item: T):
        """
        Adds an item to the buffer.

        :param item: the item to add
        """
        with self._flush_lock:
            if self._closed:
                raise ValueError("Batcher is stopped, can no longer add items")

            self._buffer.append(item)

            if len(self._buffer) >= self.max_batch_size:
                self._flush_lock.notify_all()

    @property
    def current_batch_size(self) -> int:
        """
        Returns the current number of items in the buffer waiting to be flushed.
        """
        return len(self._buffer)

    def run(self):
        """
        Runs the event loop that flushes the buffer to the handler based on the configured rules, and blocks until
        ``close()`` is called. This method is meant to be run in a separate thread.
        """
        while not self._closed:
            with self._flush_lock:
                # wait returns once either the condition is notified (in which case wait returns True, indicating that
                # something has triggered a flush manually), or the timeout expires (in which case wait returns False)
                self._flush_lock.wait(self.max_flush_interval)

                # if _flush_condition was notified because close() was called, we should still make sure we flush the
                # last batch

                # perform the flush, if there are any items in the buffer
                if not self._buffer:
                    continue

                batch = self._buffer.copy()
                self._buffer.clear()

            # we can call the processor outside the lock so we can continue adding items into the next batch without
            # waiting on the processor to return.
            try:
                self.handler(batch)
            except Exception as e:
                LOG.error(
                    "Unhandled exception while processing a batch: %s",
                    e,
                    exc_info=LOG.isEnabledFor(logging.DEBUG),
                )

        # this marks that the main control loop is done
        return

    def close(self):
        """
        Triggers a close of the batcher, which will cause one last flush, and then end the main event loop.
        """
        with self._flush_lock:
            if self._closed:
                return
            self._closed = True
            self._flush_lock.notify_all()
