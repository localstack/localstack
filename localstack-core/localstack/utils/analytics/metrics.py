from __future__ import annotations

import datetime
import logging
import threading
from abc import ABC, abstractmethod
from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Optional, Union, overload

from localstack import config
from localstack.runtime import hooks
from localstack.utils.analytics import get_session_id
from localstack.utils.analytics.events import Event, EventMetadata
from localstack.utils.analytics.publisher import AnalyticsClientPublisher

LOG = logging.getLogger(__name__)


@dataclass(frozen=True)
class MetricRegistryKey:
    namespace: str
    name: str


@dataclass(frozen=True)
class CounterPayload:
    """An immutable snapshot of a counter metric at the time of collection."""

    namespace: str
    name: str
    value: int
    type: str
    labels: Optional[dict[str, Union[str, float]]] = None

    def as_dict(self) -> dict[str, Any]:
        result = {
            "namespace": self.namespace,
            "name": self.name,
            "value": self.value,
            "type": self.type,
        }

        if self.labels:
            # Convert labels to the expected format (label_1, label_1_value, etc.)
            for i, (label_name, label_value) in enumerate(self.labels.items(), 1):
                result[f"label_{i}"] = label_name
                result[f"label_{i}_value"] = label_value

        return result


@dataclass
class MetricPayload:
    """
    Stores all metric payloads collected during the execution of the LocalStack emulator.
    Currently, supports only counter-type metrics, but designed to accommodate other types in the future.
    """

    _payload: list[CounterPayload]  # support for other metric types may be added in the future.

    @property
    def payload(self) -> list[CounterPayload]:
        return self._payload

    def __init__(self, payload: list[CounterPayload]):
        self._payload = payload

    def as_dict(self) -> dict[str, list[dict[str, Any]]]:
        return {"metrics": [payload.as_dict() for payload in self._payload]}


class MetricRegistry:
    """
    A Singleton class responsible for managing all registered metrics.
    Provides methods for retrieving and collecting metrics.
    """

    _instance: "MetricRegistry" = None
    _mutex: threading.Lock = threading.Lock()

    def __new__(cls):
        # avoid locking if the instance already exist
        if cls._instance is None:
            with cls._mutex:
                # Prevents race conditions when multiple threads enter the first check simultaneously
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        if not hasattr(self, "_registry"):
            self._registry = dict()

    @property
    def registry(self) -> dict[MetricRegistryKey, "Metric"]:
        return self._registry

    def register(self, metric: Metric) -> None:
        """
        Registers a new metric.

        :param metric: The metric instance to register.
        :type metric: Metric
        :raises TypeError: If the provided metric is not an instance of `Metric`.
        :raises ValueError: If a metric with the same name already exists.
        """
        if not isinstance(metric, Metric):
            raise TypeError("Only subclasses of `Metric` can be registered.")

        if not metric.namespace:
            raise ValueError("Metric 'namespace' must be defined and non-empty.")

        registry_unique_key = MetricRegistryKey(namespace=metric.namespace, name=metric.name)
        if registry_unique_key in self._registry:
            raise ValueError(
                f"A metric named '{metric.name}' already exists in the '{metric.namespace}' namespace"
            )

        self._registry[registry_unique_key] = metric

    def collect(self) -> MetricPayload:
        """
        Collects all registered metrics.
        """
        payload = [
            metric
            for metric_instance in self._registry.values()
            for metric in metric_instance.collect()
        ]

        return MetricPayload(payload=payload)


class Metric(ABC):
    """
    Base class for all metrics (e.g., Counter, Gauge).

    Each subclass must implement the `collect()` method.
    """

    _namespace: str
    _name: str

    def __init__(self, namespace: str, name: str):
        if not namespace or namespace.strip() == "":
            raise ValueError("Namespace must be non-empty string.")
        self._namespace = namespace

        if not name or name.strip() == "":
            raise ValueError("Metric name must be non-empty string.")
        self._name = name

    @property
    def namespace(self) -> str:
        return self._namespace

    @property
    def name(self) -> str:
        return self._name

    @abstractmethod
    def collect(
        self,
    ) -> list[CounterPayload]:  # support for other metric types may be added in the future.
        """
        Collects and returns metric data. Subclasses must implement this to return collected metric data.
        """
        pass


class BaseCounter:
    """
    A thread-safe counter for any kind of tracking.
    This class should not be instantiated directly, use the Counter class instead.
    """

    _mutex: threading.Lock
    _count: int

    def __init__(self):
        super(BaseCounter, self).__init__()
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


class CounterMetric(Metric, BaseCounter):
    """
    A thread-safe counter for tracking occurrences of an event without labels.
    This class should not be instantiated directly, use the Counter class instead.
    """

    _type: str

    def __init__(self, namespace: str, name: str):
        Metric.__init__(self, namespace=namespace, name=name)
        BaseCounter.__init__(self)

        self._type = "counter"
        MetricRegistry().register(self)

    def collect(self) -> list[CounterPayload]:
        """Collects the metric unless events are disabled."""
        if config.DISABLE_EVENTS:
            return list()

        if self._count == 0:
            # Return an empty list if the count is 0, as there are no metrics to send to the analytics backend.
            return list()

        return [
            CounterPayload(
                namespace=self._namespace, name=self.name, value=self._count, type=self._type
            )
        ]


class LabeledCounterMetric(Metric):
    """
    A labeled counter that tracks occurrences of an event across different label combinations.
    This class should not be instantiated directly, use the Counter class instead.
    """

    _type: str
    _unit: str
    _labels: list[str]
    _label_values: tuple[Optional[Union[str, float]], ...]
    _counters_by_label_values: defaultdict[tuple[Optional[Union[str, float]], ...], BaseCounter]

    def __init__(self, namespace: str, name: str, labels: list[str]):
        super(LabeledCounterMetric, self).__init__(namespace=namespace, name=name)

        if not labels:
            raise ValueError("At least one label is required; the labels list cannot be empty.")

        if any(not label for label in labels):
            raise ValueError("Labels must be non-empty strings.")

        if len(labels) > 8:
            raise ValueError("A maximum of 8 labels are allowed.")

        self._type = "counter"
        self._labels = labels
        self._counters_by_label_values = defaultdict(BaseCounter)
        MetricRegistry().register(self)

    def labels(self, **kwargs: Union[str, float, None]) -> BaseCounter:
        """
        Create a scoped counter instance with specific label values.

        This method assigns values to the predefined labels of a labeled counter and returns
        a BaseCounter object that allows tracking metrics for that specific
        combination of label values.

        :raises ValueError:
            - If the set of keys provided labels does not match the expected set of labels.
        """
        if set(self._labels) != set(kwargs.keys()):
            raise ValueError(f"Expected labels {self._labels}, got {list(kwargs.keys())}")

        _label_values = tuple(kwargs[label] for label in self._labels)

        return self._counters_by_label_values[_label_values]

    def collect(self) -> list[CounterPayload]:
        if config.DISABLE_EVENTS:
            return list()

        payload = []
        num_labels = len(self._labels)

        for label_values, counter in self._counters_by_label_values.items():
            if counter.count == 0:
                continue  # Skip items with a count of 0, as they should not be sent to the analytics backend.

            if len(label_values) != num_labels:
                raise ValueError(
                    f"Label count mismatch: expected {num_labels} labels {self._labels}, "
                    f"but got {len(label_values)} values {label_values}."
                )

            # Create labels dictionary
            labels_dict = {
                label_name: label_value
                for label_name, label_value in zip(self._labels, label_values)
            }

            payload.append(
                CounterPayload(
                    namespace=self._namespace,
                    name=self.name,
                    value=counter.count,
                    type=self._type,
                    labels=labels_dict,
                )
            )

        return payload


class Counter:
    """
    A factory class for creating counter instances.

    This class provides a flexible way to create either a simple counter
    (`CounterMetric`) or a labeled counter (`LabeledCounterMetric`) based on
    whether labels are provided.
    """

    @overload
    def __new__(cls, namespace: str, name: str) -> CounterMetric:
        return CounterMetric(namespace=namespace, name=name)

    @overload
    def __new__(cls, namespace: str, name: str, labels: list[str]) -> LabeledCounterMetric:
        return LabeledCounterMetric(namespace=namespace, name=name, labels=labels)

    def __new__(
        cls, namespace: str, name: str, labels: Optional[list[str]] = None
    ) -> Union[CounterMetric, LabeledCounterMetric]:
        if labels is not None:
            return LabeledCounterMetric(namespace=namespace, name=name, labels=labels)
        return CounterMetric(namespace=namespace, name=name)


@hooks.on_infra_shutdown()
def publish_metrics() -> None:
    """
    Collects all the registered metrics and immediately sends them to the analytics service.
    Skips execution if event tracking is disabled (`config.DISABLE_EVENTS`).

    This function is automatically triggered on infrastructure shutdown.
    """
    if config.DISABLE_EVENTS:
        return

    collected_metrics = MetricRegistry().collect()
    if not collected_metrics.payload:  # Skip publishing if no metrics remain after filtering
        return

    metadata = EventMetadata(
        session_id=get_session_id(),
        client_time=str(datetime.datetime.now()),
    )

    if collected_metrics:
        publisher = AnalyticsClientPublisher()
        publisher.publish(
            [Event(name="ls_metrics", metadata=metadata, payload=collected_metrics.as_dict())]
        )
