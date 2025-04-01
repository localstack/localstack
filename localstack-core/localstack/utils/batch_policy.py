import copy
import time
from typing import Generic, List, Optional, TypeVar, overload

from pydantic import Field
from pydantic.dataclasses import dataclass

T = TypeVar("T")

# alias to signify whether a batch policy has been triggered
BatchPolicyTriggered = bool


# TODO: Add batching on bytes as well.
@dataclass
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

    max_count: Optional[int] = Field(default=None, description="Maximum number of items", ge=0)
    max_window: Optional[float] = Field(
        default=None, description="Maximum time window in seconds", ge=0
    )

    _triggered: bool = Field(default=False, init=False)
    _last_batch_time: float = Field(default_factory=time.monotonic, init=False)
    _batch: list[T] = Field(default_factory=list, init=False)

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
    def add(self, items: List[T], *, deep_copy: bool = False) -> BatchPolicyTriggered: ...

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
