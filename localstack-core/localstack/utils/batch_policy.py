import copy
import time
from functools import cached_property
from typing import Callable, Generic, Optional, TypeVar

T = TypeVar("T")


class Batcher(Generic[T]):
    max_count: int | None
    max_window: int | None
    max_bytes: int | None

    triggered: bool
    last_batch_time: float
    bytes_tally: int
    _check_batch_policy: Callable[[], bool]

    batch: list[T]

    def __init__(
        self,
        max_count: Optional[int] = None,
        max_window: Optional[int | float] = None,
        max_bytes: Optional[int] = None,
    ):
        # Define the batch policy
        self.max_count = max_count
        self.max_window = max_window
        self.max_bytes = max_bytes

        # Whether the batch policy has been triggered
        self.triggered = False

        self.last_batch_time = time.monotonic()

        self.batch = []

    @cached_property
    def _check_batch_policy(self) -> Callable[[], bool]:
        conds: list[Callable[[], bool]] = []
        if self.max_count is not None and self.max_count > 0:
            conds.append(lambda: len(self.batch) >= self.max_count)

        if self.max_window is not None and self.max_window >= 0:
            conds.append(lambda: self.period >= self.max_window)

        if self.max_bytes is not None and self.max_bytes > 0:
            conds.append(lambda: self.bytes_tally >= self.max_bytes)

        # Just return true if no conditions are set
        if not conds:
            return lambda: True

        def _check_policy_exceeded():
            self.triggered = any(condition() for condition in conds)
            return self.triggered

        return _check_policy_exceeded

    @property
    def period(self) -> float:
        return time.monotonic() - self.last_batch_time

    def add(self, item: T, *, cache_deep_copy: bool = False) -> bool:
        if cache_deep_copy:
            item = copy.deepcopy(item)
        self.batch.append(item)

        return self._check_batch_policy()

    def add_items(self, items: list[T], *, cache_deep_copy: bool = False) -> bool:
        if cache_deep_copy:
            items = copy.deepcopy(items)
        self.batch.extend(items)

        return self._check_batch_policy()

    def duration_until_next_batch(self) -> float:
        # -1 means the time has surpassed
        return max(self.max_window or 0 - self.period, -1)

    def flush(self) -> list[T]:
        result = []
        if not self.max_count:
            result = self.batch.copy()
            self.batch.clear()
        else:
            batch_size = min(self.max_count, len(self.batch))
            result = self.batch[:batch_size].copy()
            self.batch = self.batch[batch_size:]

        self.last_batch_time = time.monotonic()
        self.bytes_tally = 0
        self.triggered = False

        return result

    def calculate_bytes(self, item: T) -> int:
        if hasattr(item, "get_bytes") and callable(item.get_bytes):
            return item.get_bytes()

        return -1
