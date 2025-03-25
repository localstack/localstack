import time

import pytest

from localstack.utils.batch_policy import Batcher


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

    def test_add_multple_items(self):
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
