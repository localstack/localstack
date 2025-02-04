import threading
from re import escape

import pytest

from localstack.utils.analytics.metrics import (
    Counter,
    MetricRegistry,
)


def test_metric_registry_singleton():
    registry_1 = MetricRegistry()
    registry_2 = MetricRegistry()
    assert registry_1 is registry_2, "Only one instance of MetricRegistry should exist at any time"


def test_counter_increment():
    counter = Counter(name="test_counter")
    counter.increment()
    counter.increment(value=3)
    collected = counter.collect()
    assert collected[0]["value"] == 4, (
        f"Unexpected counter value: expected 4, got {collected[0]['value']}"
    )


def test_counter_reset():
    counter = Counter(name="test_counter")
    counter.increment(value=5)
    counter.reset()
    collected = counter.collect()
    assert collected == list(), f"Unexpected counter value: expected 0, got {collected}"


def test_labeled_counter_increment():
    labeled_counter = Counter(name="test_multilabel_counter", labels=["status"])
    labeled_counter.labels(status="success").increment(value=2)
    labeled_counter.labels(status="error").increment(value=3)
    collected_metrics = labeled_counter.collect()

    assert any(
        metric["value"] == 2 for metric in collected_metrics if metric["label_1_value"] == "success"
    ), "Unexpected counter value for label success"
    assert any(
        metric["value"] == 3 for metric in collected_metrics if metric["label_1_value"] == "error"
    ), "Unexpected counter value for label error"


def test_labeled_counter_reset():
    labeled_counter = Counter(name="test_multilabel_counter", labels=["status"])
    labeled_counter.labels(status="success").increment(value=5)
    labeled_counter.labels(status="error").increment(value=4)

    labeled_counter.labels(status="success").reset()

    collected_metrics = labeled_counter.collect()

    assert all(metric["label_1_value"] != "success" for metric in collected_metrics), (
        "Metric for label 'success' should not appear after reset."
    )

    assert any(
        metric["value"] == 4 for metric in collected_metrics if metric["label_1_value"] == "error"
    ), "Unexpected counter value for label error"


def test_counter_when_events_disabled(disable_analytics):
    counter = Counter(name="test_counter")
    counter.increment(value=10)
    assert counter.collect() == [], "Counter should not collect any data"


def test_labeled_counter_when_events_disabled_(disable_analytics):
    labeled_counter = Counter(name="test_multilabel_counter", labels=["status"])
    labeled_counter.labels(status="status").increment(value=5)
    assert labeled_counter.collect() == [], "Counter should not collect any data"


def test_metric_registry_register_and_collect():
    counter = Counter(name="test_counter")
    registry = MetricRegistry()

    # Ensure the counter is already registered
    assert counter.name in registry._registry, "Counter should automatically register itself"
    counter.increment(value=7)
    collected = registry.collect()
    assert any(metric["value"] == 7 for metric in collected["metrics"]), (
        f"Unexpected collected metrics: {collected}"
    )


def test_metric_registry_register_duplicate_counter():
    counter = Counter(name="test_counter")
    registry = MetricRegistry()

    # Attempt to manually register the counter again, expecting a ValueError
    with pytest.raises(ValueError, match=f"Metric '{counter.name}' already exists."):
        registry.register(counter)


def test_thread_safety():
    counter = Counter(name="test_counter")

    def increment():
        for _ in range(1000):
            counter.increment()

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
    with pytest.raises(ValueError, match="A maximum of 8 labels are allowed."):
        Counter(name="test_counter", labels=["l1", "l2", "l3", "l4", "l5", "l6", "l7", "l8", "l9"])


def test_counter_raises_error_if_labels_contain_empty_strings():
    """Ensure that a labeled counter cannot be instantiated with empty or whitespace-only labels."""
    with pytest.raises(ValueError, match="Labels must be non-empty strings."):
        Counter(name="test_labeled_counter", labels=["status", ""])


def test_labels_method_raises_error_if_label_value_is_empty():
    """Ensure that the labels method raises an error if any client-defined label is empty."""
    with pytest.raises(ValueError, match=escape("Label values must be non-empty strings.")):
        Counter(name="test_labeled_counter", labels=["status"]).labels(status="")


def test_counter_raises_error_if_name_is_empty():
    with pytest.raises(ValueError, match="Name is required and cannot be empty."):
        Counter(name="")
