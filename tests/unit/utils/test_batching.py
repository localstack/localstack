import threading
import time
from queue import Queue

import pytest

from localstack.utils.batching import AsyncBatcher, Batcher


class SimpleItem:
    def __init__(self, number=10):
        self.number = number


class TestBatcher:
    def test_add_single_item(self):
        batcher = Batcher(max_count=2)

        assert not batcher.add("item1")
        assert batcher.get_current_size() == 1
        assert not batcher.is_triggered()

        assert batcher.add("item2")
        assert batcher.is_triggered()

        result = batcher.flush()
        assert result == ["item1", "item2"]
        assert batcher.get_current_size() == 0

    def test_add_multiple_items(self):
        batcher = Batcher(max_count=3)

        assert not batcher.add(["item1", "item2"])
        assert batcher.get_current_size() == 2
        assert not batcher.is_triggered()

        assert batcher.add(["item3", "item4"])  # exceeds max_count
        assert batcher.is_triggered()
        assert batcher.get_current_size() == 4

        result = batcher.flush()
        assert result == ["item1", "item2", "item3", "item4"]
        assert batcher.get_current_size() == 0

        assert batcher.add(["item1", "item2", "item3", "item4"])
        assert batcher.flush() == ["item1", "item2", "item3", "item4"]
        assert not batcher.is_triggered()

    def test_max_count_limit(self):
        batcher = Batcher(max_count=3)

        assert not batcher.add("item1")
        assert not batcher.add("item2")
        assert batcher.add("item3")

        assert batcher.is_triggered()
        assert batcher.get_current_size() == 3

        result = batcher.flush()
        assert result == ["item1", "item2", "item3"]
        assert batcher.get_current_size() == 0

        assert not batcher.add("item4")
        assert not batcher.add("item5")
        assert batcher.get_current_size() == 2

    def test_max_window_limit(self):
        max_window = 0.5
        batcher = Batcher(max_window=max_window)

        assert not batcher.add("item1")
        assert batcher.get_current_size() == 1
        assert not batcher.is_triggered()

        assert not batcher.add("item2")
        assert batcher.get_current_size() == 2
        assert not batcher.is_triggered()

        time.sleep(max_window + 0.1)

        assert batcher.add("item3")
        assert batcher.is_triggered()
        assert batcher.get_current_size() == 3

        result = batcher.flush()
        assert result == ["item1", "item2", "item3"]
        assert batcher.get_current_size() == 0

    def test_multiple_policies(self):
        batcher = Batcher(max_count=5, max_window=2.0)

        item1 = SimpleItem(1)
        for _ in range(5):
            batcher.add(item1)
        assert batcher.is_triggered()

        result = batcher.flush()
        assert result == [item1, item1, item1, item1, item1]
        assert batcher.get_current_size() == 0

        batcher.add(item1)
        assert not batcher.is_triggered()

        item2 = SimpleItem(10)

        time.sleep(2.1)
        batcher.add(item2)
        assert batcher.is_triggered()

        result = batcher.flush()
        assert result == [item1, item2]

    def test_flush(self):
        batcher = Batcher(max_count=10)

        batcher.add("item1")
        batcher.add("item2")
        batcher.add("item3")

        result = batcher.flush()
        assert result == ["item1", "item2", "item3"]
        assert batcher.get_current_size() == 0

        batcher.add("item4")
        result = batcher.flush()
        assert result == ["item4"]
        assert batcher.get_current_size() == 0

    @pytest.mark.parametrize(
        "max_count,max_window",
        [(0, 10), (10, 0), (None, None)],
    )
    def test_no_limits(self, max_count, max_window):
        if max_count or max_window:
            batcher = Batcher(max_count=max_count, max_window=max_window)
        else:
            batcher = Batcher()

        assert batcher.is_triggered()  # no limit always returns true

        assert batcher.add("item1")
        assert batcher.get_current_size() == 1
        assert batcher.is_triggered()

        assert batcher.add(["item2", "item3"])
        assert batcher.get_current_size() == 3
        assert batcher.is_triggered()

        result = batcher.flush()
        assert result == ["item1", "item2", "item3"]
        assert batcher.get_current_size() == 0

    def test_triggered_state(self):
        batcher = Batcher(max_count=2)

        assert not batcher.add("item1")
        assert not batcher.is_triggered()

        assert batcher.add("item2")
        assert batcher.is_triggered()

        assert batcher.add("item3")
        assert batcher.flush() == ["item1", "item2", "item3"]
        assert batcher.get_current_size() == 0
        assert not batcher.is_triggered()

    def test_max_count_partial_flush(self):
        batcher = Batcher(max_count=2)

        assert batcher.add(["item1", "item2", "item3", "item4"])
        assert batcher.is_triggered()

        assert batcher.flush(partial=True) == ["item1", "item2"]
        assert batcher.get_current_size() == 2

        assert batcher.flush(partial=True) == ["item3", "item4"]
        assert not batcher.is_triggered()  # early flush

        assert batcher.flush() == []
        assert batcher.get_current_size() == 0
        assert not batcher.is_triggered()

    def test_deep_copy(self):
        original = {"key": "value"}
        batcher = Batcher(max_count=2)

        batcher.add(original, deep_copy=True)

        original["key"] = "modified"

        batch = batcher.flush()
        assert batch[0]["key"] == "value"


class TestAsyncBatcher:
    def test_basic(self):
        calls = Queue()

        def collect(_batch: list):
            calls.put(_batch)

        buffer = AsyncBatcher(collect, max_batch_size=2, max_flush_interval=1000)

        t = threading.Thread(target=buffer.run)
        t.start()

        try:
            e1 = "e1"
            e2 = "e2"
            e3 = "e3"

            buffer.add(e1)
            buffer.add(e2)

            c1 = calls.get(timeout=2)
            assert len(c1) == 2

            buffer.add(e3)  # should flush after close despite flush_size = 2
        finally:
            buffer.close()

        c2 = calls.get(timeout=2)
        assert len(c2) == 1

        assert c1[0] == e1
        assert c1[1] == e2
        assert c2[0] == e3

        t.join(10)

    def test_interval(self):
        calls = Queue()

        def collect(_batch: list):
            calls.put(_batch)

        buffer = AsyncBatcher(collect, max_batch_size=10, max_flush_interval=1)

        t = threading.Thread(target=buffer.run)
        t.start()

        try:
            e1 = "e1"
            e2 = "e2"
            e3 = "e3"
            e4 = "e4"

            buffer.add(e1)
            buffer.add(e2)
            c1 = calls.get(timeout=2)

            buffer.add(e3)
            buffer.add(e4)
            c2 = calls.get(timeout=2)
        finally:
            buffer.close()

        assert len(c1) == 2
        assert len(c2) == 2
        t.join(10)
