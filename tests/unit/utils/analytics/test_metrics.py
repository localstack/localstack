import threading

import pytest

from localstack.utils.analytics.metrics import Counter, MockCounter, get_metric_registry


def test_metric_registry_singleton():
    registry_1 = get_metric_registry()
    registry_2 = get_metric_registry()
    assert registry_1 is registry_2, "Only one instance of MetricRegistry should exist at any time"


def test_counter_increment(counter):
    counter.inc()
    counter.inc(value=3)
    collected = counter.collect()
    assert collected[0]["value"] == 4, (
        f"Unexpected counter value: expected 4, got {collected[0]['value']}"
    )


def test_counter_reset(counter):
    counter.inc(value=5)
    counter.reset()
    collected = counter.collect()
    assert collected[0]["value"] == 0, (
        f"Unexpected counter value: expected 0, got {collected[0]['value']}"
    )


def test_labeled_counter_increment(labeled_counter):
    labeled_counter.labels(status="success").inc(value=2)
    labeled_counter.labels(status="error").inc(value=3)
    collected = labeled_counter.collect()
    assert any(metric["value"] == 2 for metric in collected if metric["label_1"] == "success"), (
        "Unexpected counter value for label success"
    )
    assert any(metric["value"] == 3 for metric in collected if metric["label_1"] == "error"), (
        "Unexpected counter value for label error"
    )


def test_labeled_counter_reset(labeled_counter):
    labeled_counter.labels(status="success").inc(value=5)
    labeled_counter.labels(status="error").inc(value=4)

    labeled_counter.labels(status="success").reset()

    collected = labeled_counter.collect()
    assert any(metric["value"] == 0 for metric in collected if metric["label_1"] == "success"), (
        "Unexpected counter value for label success"
    )

    assert any(metric["value"] == 4 for metric in collected if metric["label_1"] == "error"), (
        "Unexpected counter value for label error"
    )


def test_mock_counter_when_events_disabled(disable_analytics, counter):
    assert isinstance(counter, MockCounter), "Should return a MockCounter when events are disabled"
    counter.inc(value=10)
    assert counter.collect() == [], "MockCounter should not collect any data"


def test_metric_registry_register_and_collect(counter):
    registry = get_metric_registry()

    # Ensure the counter is already registered
    assert counter.full_name in registry._registry, "Counter should automatically register itself"
    counter.inc(value=7)
    collected = registry.collect()
    assert any(metric["value"] == 7 for metric in collected["metrics"]), (
        f"Unexpected collected metrics: {collected}"
    )


def test_metric_registry_register_duplicate_counter(counter):
    registry = get_metric_registry()

    # Attempt to manually register the counter again, expecting a ValueError
    with pytest.raises(ValueError, match=f"Metric '{counter.full_name}' already exists."):
        registry.register(counter)


def test_thread_safety(counter):
    def increment():
        for _ in range(1000):
            counter.inc()

    threads = [threading.Thread(target=increment) for _ in range(5)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    collected = counter.collect()
    assert collected[0]["value"] == 5000, (
        f"Unexpected counter value: expected 5000, got {collected[0]['value']}"
    )


def test_max_labels_limit():
    with pytest.raises(ValueError, match="A maximum of 5 labels are allowed."):
        Counter(name="test_counter", labels=["l1", "l2", "l3", "l4", "l5", "l6"])


def test_labeled_counter_raises_error_if_inc_called_without_labels(labeled_counter):
    """Ensure calling inc() directly on a labeled counter raises a ValueError."""
    from re import escape  # Imported to escape special characters in the error message

    with pytest.raises(
        ValueError, match=escape("This counter requires labels, use .labels() instead.")
    ):
        labeled_counter.inc(value=5)
