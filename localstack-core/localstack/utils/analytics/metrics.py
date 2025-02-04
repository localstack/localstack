from __future__ import annotations

import datetime
import logging
import threading
from abc import ABC, abstractmethod
from collections import defaultdict
from typing import Dict, List, Optional, Tuple, Union, overload

from localstack import config
from localstack.runtime import hooks
from localstack.utils.analytics import get_session_id
from localstack.utils.analytics.events import Event, EventMetadata
from localstack.utils.analytics.publisher import AnalyticsClientPublisher

LOG = logging.getLogger(__name__)


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
    def registry(self) -> Dict[str, "Metric"]:
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

        if metric.name in self._registry:
            raise ValueError(f"Metric '{metric.name}' already exists.")

        self._registry[metric.name] = metric

    def collect(self) -> Dict[str, List[Dict[str, Union[str, int]]]]:
        """
        Collects all registered metrics.
        """
        return {
            "metrics": [
                metric
                for metric_instance in self._registry.values()
                for metric in metric_instance.collect()
            ]
        }


class Metric(ABC):
    """
    Base class for all metrics (e.g., Counter, Gauge).

    Each subclass must implement the `collect()` method.
    """

    _name: str

    @property
    def name(self) -> str:
        """
        Retrieves the fully qualified metric name.
        """
        return self._name

    @name.setter
    def name(self, value: str) -> None:
        """
        Validates and sets the full metric name.

        :raises ValueError: If the name is empty or invalid.
        """
        if not value or value.strip() == "":
            raise ValueError("Metric must have a valid name.")
        self._name = value

    @abstractmethod
    def collect(self) -> List[Dict[str, Union[str, int]]]:
        """
        Collects and returns metric data. Subclasses must implement this to return collected metric data.
        """
        pass


class _Counter:
    """
    A thread-safe counter for any kind of tracking.
    """

    _mutex: threading.Lock
    _count: int

    def __init__(self):
        super(_Counter, self).__init__()
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


class _CounterMetric(Metric, _Counter):
    """
    A thread-safe counter for tracking occurrences of an event without labels.
    """

    _namespace: Optional[str]
    _name: str
    _type: str

    def __init__(self, name: str, namespace: Optional[str] = ""):
        super(_CounterMetric, self).__init__()
        if not name:
            raise ValueError("Name is required and cannot be empty.")

        self._name = name.strip()
        self._namespace = namespace.strip() if namespace else ""
        self._type = "counter"
        MetricRegistry().register(self)

    def collect(self) -> List[Dict[str, Union[str, int]]]:
        """Collects the metric unless events are disabled."""
        if config.DISABLE_EVENTS:
            return list()

        if self._count == 0:
            # Return an empty list if the count is 0, as there are no metrics to send to the analytics backend.
            return list()
        return [
            {
                "namespace": self._namespace,
                "name": self._name,
                "value": self._count,
                "type": self._type,
            }
        ]


class _LabeledCounterMetric(Metric):
    """
    A labeled counter that tracks occurrences of an event across different label combinations.
    """

    _namespace: Optional[str]
    _name: str
    _type: str
    _unit: str
    _labels: list[str]
    _label_values: tuple[Optional[str], ...]
    _counters_by_label_values: defaultdict[Tuple[str, ...], _Counter]

    def __init__(self, name: str, labels: List[str] = list, namespace: Optional[str] = ""):
        if not name:
            raise ValueError("Name is required and cannot be empty.")

        if any(not label for label in labels):
            raise ValueError("Labels must be non-empty strings.")

        if len(labels) > 8:
            raise ValueError("A maximum of 8 labels are allowed.")

        self._name = name.strip()
        self._namespace = namespace.strip() if namespace else ""
        self._type = "counter"
        self._labels = labels
        self._counters_by_label_values = defaultdict(_Counter)
        MetricRegistry().register(self)

    def labels(self, **kwargs: str) -> _Counter:
        """
        Create a scoped counter instance with specific label values.

        This method assigns values to the predefined labels of a labeled counter and returns
        a _Counter object (``) that allows tracking metrics for that specific
        combination of label values.

        The proxy ensures that increments and resets are scoped to the given label values,
        enforcing proper metric categorization.

        :raises ValueError:
            - If the number of provided labels does not match the expected count.
            - If any of the provided labels are empty strings.
        """
        if set(self._labels) != set(kwargs.keys()):
            raise ValueError(f"Expected labels {self._labels}, got {list(kwargs.keys())}")

        _label_values = tuple(kwargs[label] for label in self._labels)

        if any(not label for label in _label_values):
            raise ValueError("Label values must be non-empty strings.")

        return self._counters_by_label_values[_label_values]

    def _as_list(self) -> List[Dict[str, Union[str, int]]]:
        num_labels = len(self._labels)

        static_key_label_value = [f"label_{i + 1}_value" for i in range(num_labels)]
        static_key_label = [f"label_{i + 1}" for i in range(num_labels)]

        collected_metrics = []

        for label_values, counter in self._counters_by_label_values.items():
            if counter.count == 0:
                continue  # Skip items with a count of 0, as they should not be sent to the analytics backend.

            if len(label_values) != num_labels:
                raise ValueError(
                    f"Label count mismatch: expected {num_labels} labels {self._labels}, "
                    f"but got {len(label_values)} values {label_values}."
                )

            collected_metrics.append(
                {
                    "namespace": self._namespace,
                    "name": self._name,
                    "value": counter.count,
                    "type": self._type,
                    **dict(zip(static_key_label_value, label_values)),
                    **dict(zip(static_key_label, self._labels)),
                }
            )

        return collected_metrics

    def collect(self) -> List[Dict[str, Union[str, int]]]:
        if config.DISABLE_EVENTS:
            return list()
        return self._as_list()


class Counter:
    """
    A factory class for creating counter instances.

    This class provides a flexible way to create either a simple counter
    (`_SimpleCounter`) or a labeled counter (`_LabeledCounter`) based on
    whether labels are provided.
    """

    @overload
    def __new__(cls, name: str, namespace: Optional[str] = "") -> _CounterMetric:
        return _CounterMetric(namespace=namespace, name=name)

    @overload
    def __new__(
        cls, name: str, labels: List[str], namespace: Optional[str] = ""
    ) -> _LabeledCounterMetric:
        return _LabeledCounterMetric(namespace=namespace, name=name, labels=labels)

    def __new__(
        cls, name: str, namespace: Optional[str] = "", labels: Optional[List[str]] = None
    ) -> Union[_CounterMetric, _LabeledCounterMetric]:
        if labels:
            return _LabeledCounterMetric(namespace=namespace, name=name, labels=labels)
        return _CounterMetric(namespace=namespace, name=name)


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
    if not collected_metrics["metrics"]:  # Skip publishing if no metrics remain after filtering
        return

    metadata = EventMetadata(
        session_id=get_session_id(),
        client_time=str(datetime.datetime.now()),
    )

    if collected_metrics:
        publisher = AnalyticsClientPublisher()
        publisher.publish([Event(name="ls_metrics", metadata=metadata, payload=collected_metrics)])