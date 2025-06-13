import threading

import pytest

from localstack.utils.analytics.metrics import (
    Counter,
    LabeledCounter,
    MetricRegistry,
    MetricRegistryKey,
)


def test_metric_registry_singleton():
    registry_1 = MetricRegistry()
    registry_2 = MetricRegistry()
    assert registry_1 is registry_2, "Only one instance of MetricRegistry should exist at any time"


def test_counter_increment():
    counter = Counter(namespace="test_namespace", name="test_counter")
    counter.increment()
    counter.increment(value=3)
    collected = counter.collect()
    assert collected[0].value == 4, (
        f"Unexpected counter value: expected 4, got {collected[0]['value']}"
    )


def test_counter_reset():
    counter = Counter(namespace="test_namespace", name="test_counter")
    counter.increment(value=5)
    counter.reset()
    collected = counter.collect()
    assert collected == list(), f"Unexpected counter value: expected 0, got {collected}"


def test_labeled_counter_increment():
    labeled_counter = LabeledCounter(
        namespace="test_namespace", name="test_multilabel_counter", labels=["status"]
    )
    labeled_counter.labels(status="success").increment(value=2)
    labeled_counter.labels(status="error").increment(value=3)
    collected_metrics = labeled_counter.collect()

    assert any(
        metric.value == 2 and metric.labels and metric.labels.get("status") == "success"
        for metric in collected_metrics
    ), "Unexpected counter value for label success"

    assert any(
        metric.value == 3 and metric.labels and metric.labels.get("status") == "error"
        for metric in collected_metrics
    ), "Unexpected counter value for label error"


def test_labeled_counter_reset():
    labeled_counter = LabeledCounter(
        namespace="test_namespace", name="test_multilabel_counter", labels=["status"]
    )
    labeled_counter.labels(status="success").increment(value=5)
    labeled_counter.labels(status="error").increment(value=4)

    labeled_counter.labels(status="success").reset()

    collected_metrics = labeled_counter.collect()

    # Assert that no metric with label "success" is present anymore
    assert all(
        not metric.labels or metric.labels.get("status") != "success"
        for metric in collected_metrics
    ), "Metric for label 'success' should not appear after reset."

    # Assert that metric with label "error" is still there with correct value
    assert any(
        metric.value == 4 and metric.labels and metric.labels.get("status") == "error"
        for metric in collected_metrics
    ), "Unexpected counter value for label error"


def test_counter_when_events_disabled(disable_analytics):
    counter = Counter(namespace="test_namespace", name="test_counter")
    counter.increment(value=10)
    assert counter.collect() == [], "Counter should not collect any data"


def test_labeled_counter_when_events_disabled_(disable_analytics):
    labeled_counter = LabeledCounter(
        namespace="test_namespace", name="test_multilabel_counter", labels=["status"]
    )
    labeled_counter.labels(status="status").increment(value=5)
    assert labeled_counter.collect() == [], "Counter should not collect any data"


def test_metric_registry_register_and_collect():
    counter = Counter(namespace="test_namespace", name="test_counter")
    registry = MetricRegistry()

    # Ensure the counter is already registered
    assert MetricRegistryKey("test_namespace", "test_counter") in registry._registry, (
        "Counter should automatically register itself"
    )
    counter.increment(value=7)
    collected_metrics = registry.collect()
    assert any(metric.value == 7 for metric in collected_metrics.payload), (
        f"Unexpected collected metrics: {collected_metrics}"
    )


def test_metric_registry_register_duplicate_counter():
    counter = Counter(namespace="test_namespace", name="test_counter")
    registry = MetricRegistry()

    # Attempt to manually register the counter again, expecting a ValueError
    with pytest.raises(
        ValueError,
        match=f"A metric named '{counter.name}' already exists in the '{counter.namespace}' namespace",
    ):
        registry.register(counter)


def test_thread_safety():
    counter = Counter(namespace="test_namespace", name="test_counter")

    def increment():
        for _ in range(1000):
            counter.increment()

    threads = [threading.Thread(target=increment) for _ in range(5)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    collected_metrics = counter.collect()
    assert collected_metrics[0].value == 5000, (
        f"Unexpected counter value: expected 5000, got {collected_metrics[0].value}"
    )


def test_max_labels_limit():
    with pytest.raises(ValueError, match="Too many labels: counters allow a maximum of 6."):
        LabeledCounter(
            namespace="test_namespace",
            name="test_counter",
            labels=["l1", "l2", "l3", "l4", "l5", "l6", "l7"],
        )


def test_counter_raises_error_if_namespace_is_empty():
    with pytest.raises(ValueError, match="Namespace must be non-empty string."):
        Counter(namespace="", name="")

    with pytest.raises(ValueError, match="Metric name must be non-empty string."):
        Counter(namespace="test_namespace", name="  ")


def test_counter_raises_error_if_name_is_empty():
    with pytest.raises(ValueError, match="Metric name must be non-empty string."):
        Counter(namespace="test_namespace", name="")

    with pytest.raises(ValueError, match="Metric name must be non-empty string."):
        Counter(namespace="test_namespace", name="  ")


def test_counter_raises_if_label_values_off():
    with pytest.raises(
        ValueError, match="At least one label is required; the labels list cannot be empty."
    ):
        LabeledCounter(namespace="test_namespace", name="test_counter", labels=[]).labels(l1="a")

    with pytest.raises(ValueError):
        LabeledCounter(namespace="test_namespace", name="test_counter", labels=["l1", "l2"]).labels(
            l1="a", non_existing="asdf"
        )

    with pytest.raises(ValueError):
        LabeledCounter(namespace="test_namespace", name="test_counter", labels=["l1", "l2"]).labels(
            l1="a"
        )

    with pytest.raises(ValueError):
        LabeledCounter(namespace="test_namespace", name="test_counter", labels=["l1", "l2"]).labels(
            l1="a", l2="b", l3="c"
        )


def test_label_kwargs_order_independent():
    labeled_counter = LabeledCounter(
        namespace="test_namespace", name="test_multilabel_counter", labels=["status", "type"]
    )
    labeled_counter.labels(status="success", type="counter").increment(value=2)
    labeled_counter.labels(type="counter", status="success").increment(value=3)
    labeled_counter.labels(type="counter", status="error").increment(value=3)
    collected_metrics = labeled_counter.collect()

    assert any(
        metric.value == 5 and metric.labels and metric.labels.get("status") == "success"
        for metric in collected_metrics
    ), "Unexpected counter value for label success"
    assert any(
        metric.value == 3 and metric.labels and metric.labels.get("status") == "error"
        for metric in collected_metrics
    ), "Unexpected counter value for label error"


def test_default_schema_version_for_counter():
    counter = Counter(namespace="test_namespace", name="test_name")
    counter.increment()
    collected_metrics = counter.collect()
    assert collected_metrics[0].schema_version == 1, (
        "Default schema_version for Counter should be 1"
    )


def test_custom_schema_version_for_counter():
    counter = Counter(namespace="test_namespace", name="test_name", schema_version=3)
    counter.increment()
    collected_metrics = counter.collect()
    assert collected_metrics[0].schema_version == 3


def test_default_schema_version_for_labeled_counter():
    labeled_counter = LabeledCounter(namespace="test_namespace", name="test_name", labels=["type"])
    labeled_counter.labels(type="success").increment()
    collected_metrics = labeled_counter.collect()
    assert collected_metrics[0].schema_version == 1, (
        "Default schema_version for LabeledCounter should be 1"
    )


def test_custom_schema_version_for_labeled_counter():
    labeled_counter = LabeledCounter(
        namespace="test_namespace",
        name="test_name",
        labels=["type"],
        schema_version=5,
    )
    labeled_counter.labels(type="success").increment()
    collected_metrics = labeled_counter.collect()
    assert collected_metrics[0].schema_version == 5
