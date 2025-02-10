from __future__ import annotations

import datetime
import logging
import threading
from abc import ABC, abstractmethod
from collections import defaultdict
from typing import Dict, List, Optional, Tuple, Union

from localstack import config
from localstack.runtime import hooks
from localstack.utils.analytics import get_session_id
from localstack.utils.analytics.events import Event, EventMetadata
from localstack.utils.analytics.publisher import AnalyticsClientPublisher

LOG = logging.getLogger(__name__)

# TODO: introduce some base abstraction for the counters after gather some initial experience working with it
#  we could probably do intermediate aggregations over time to avoid unbounded counters for very long LS sessions
#  for now, we can recommend to use config.DISABLE_EVENTS=


class MetricRegistry:
    """
    A Singleton responsible for managing all registered metrics.

    - Stores references to `Metric` instances.
    - Provides methods for retrieving and collecting metrics.
    """

    _instance: Optional[MetricRegistry] = None  # Singleton instance
    _registry: Dict[str, Metric]

    def __new__(cls) -> MetricRegistry:
        """Ensures only one instance of `MetricRegistry` exists"""
        if not cls._instance:
            cls._instance = super(MetricRegistry, cls).__new__(cls)
            cls._instance._registry = dict()  # Registry initialized here
        return cls._instance

    def register(self, metric: Metric) -> None:
        """
        Registers a new metric (Counter, Gauge, etc.).

        Args:
            metric (Metric): The metric instance to register.

        Raises:
            ValueError: If a metric with the same name already exists.
        """
        if not isinstance(metric, Metric):
            raise TypeError("Only subclasses of `Metric` can be registered.")

        if metric.full_name in self._registry:
            raise ValueError(f"Metric '{metric.full_name}' already exists.")

        self._registry[metric.full_name] = metric

    def collect(self) -> Dict[str, List[Dict[str, Union[str, int]]]]:
        """
        Collects all registered metrics.

        Returns:
            List[Dict[str, Union[str, int]]]: A flat list of all collected metrics.
        """
        return {
            "metrics": [
                metric
                for metric_instance in self._registry.values()
                for metric in metric_instance.collect()
            ]
        }


def get_metric_registry() -> MetricRegistry:
    """Ensures we always get the same instance of `MetricRegistry`."""
    return MetricRegistry()


class Metric(ABC):
    """
    Base class for all metrics (e.g., Counter, Gauge).

    Each subclass must implement the `collect()` method.
    """

    _full_name: str = None

    @property
    def full_name(self) -> str:
        """Returns the fully qualified metric name."""
        return self._full_name

    @full_name.setter
    def full_name(self, value: str) -> None:
        """
        Validates and sets the full metric name.

        Args:
            value (str): The fully qualified name to be set.

        Raises:
            ValueError: If the name is empty or invalid.
        """
        if not value or value.strip() == "":
            raise ValueError("Metric must have a valid name.")
        self._full_name = value

    @abstractmethod
    def collect(self) -> List[Dict[str, Union[str, int]]]:
        """Subclasses must implement this to return collected metric data."""
        pass


class MockCounter(Metric):
    """Mock implementation of the Counter class, used when events are disabled."""

    def labels(self, **kwargs: str) -> MockCounter:
        """Returns itself for chained calls, allowing no-op metric operations."""
        return self

    def inc(self, value: int = 1) -> None:
        """Ignores increment operations when events are disabled."""
        pass

    def reset(
        self,
    ) -> None:
        pass

    def collect(self) -> List[Dict[str, Union[str, int]]]:
        """Returns an empty list since no metrics are collected in mock mode."""
        return []


class Counter(Metric):
    """
    A thread-safe counter for tracking occurrences of an event.

    Supports both:
    - **Labeled counters** (via `.labels()`).
    - **Unlabeled counters** (direct `.inc()` calls).

    Attributes:
        _lock (threading.Lock): Ensures thread-safe operations.
        _values (defaultdict): Stores counter values, keyed by label tuples.
        _name (Optional[str]): The metric name.
        _full_name (str): The fully qualified metric name.
        _namespace (Optional[str]): The namespace for the metric.
        _labels (List[str]): The assigned label keys.
        _labels_normalization (Dict[str, str]): Maps original label names to generic `label_X` keys.
    """

    _lock: threading.Lock
    _values: defaultdict[Tuple[Optional[str], ...], int]
    _name: Optional[str]
    _full_name: str
    _namespace: Optional[str]
    _labels: Optional[List[str]]
    __labels_normalization: Dict[str, str]

    def __new__(
        cls, name: str = "", labels: Optional[List[str]] = None, namespace: str = ""
    ) -> Union[Counter, MockCounter]:
        """Returns a real or mock instance based on the `DISABLE_EVENTS` config."""
        if config.DISABLE_EVENTS:
            return MockCounter()
        return super(Counter, cls).__new__(cls)

    def __init__(self, name: str = "", labels: Optional[List[str]] = None, namespace: str = ""):
        """
        Initializes a counter.

        Args:
            name (str): The metric name.
            labels (Optional[List[str]]): List of labels (max 5). If not provided, the counter is unlabeled.
            namespace (str): The namespace for the metric.
        """
        self._lock = threading.Lock()
        self._values = defaultdict(int)

        if not name and not namespace:
            raise ValueError("Either 'name' or 'namespace' must be provided.")

        self._name = name.strip() if name else None
        self._namespace = namespace.strip() if namespace else None

        # Construct the full metric name. Validated in the base class setter
        self.full_name = "_".join(filter(None, [self._namespace, self._name])).strip("_")

        if labels:
            if len(labels) > 5:
                raise ValueError("A maximum of 5 labels are allowed.")
            self._labels_normalization = {
                label_origin: f"label_{i + 1}" for i, label_origin in enumerate(labels or [])
            }
            self._labels = list(self._labels_normalization.values())
        else:
            self._labels_normalization = {}
            self._labels = []

        get_metric_registry().register(self)

    def labels(self, **kwargs: str) -> LabeledCounter:
        """
        Returns a metric instance for specific label values.

        Args:
            kwargs (str): A dictionary of label values (e.g., `status="error"`).

        Returns:
            LabeledCounter: A labeled metric instance.

        Raises:
            ValueError: If the counter does not support labels or incorrect labels are provided.
        """
        if not self._labels:
            raise ValueError("This counter does not support labels.")

        if len(kwargs) != len(self._labels_normalization.keys()):
            raise ValueError(
                f"Expected labels {self._labels_normalization.keys()}, got {list(kwargs.keys())}"
            )

        labels = tuple(
            kwargs.get(label_key, None) for label_key in self._labels_normalization.keys()
        )
        return LabeledCounter(counter=self, labels=labels)

    def inc(self, value: int = 1, label_key: Optional[Tuple[Optional[str], ...]] = None) -> None:
        """
        Increments the counter.

        Args:
            value (int): The amount to increment (must be positive).
            label_key: Tuple of label values (only required for labeled counters).

        Raises:
            ValueError: If the value is not a positive number.
            ValueError: If incrementing a labeled counter without labels.
        """
        if value <= 0:
            raise ValueError("Increment value must be positive.")

        if self._labels and label_key is None:
            raise ValueError("This counter requires labels, use .labels() instead.")

        # Use an empty tuple for non-labeled counters
        key = label_key if label_key is not None else ()

        with self._lock:
            self._values[key] += value

    def reset(self, label_key: Optional[Tuple[Optional[str], ...]] = None) -> None:
        """
        Resets the counter to zero.

        Args:
            label_key: Tuple of label values (only required for labeled counters).

        Raises:
            ValueError: If resetting a labeled counter without labels.
        """
        if self._labels and label_key is None:
            raise ValueError("This counter requires labels, use .labels() instead.")

        # Use an empty tuple for non-labeled counters
        key = label_key if label_key is not None else ()

        with self._lock:
            self._values[key] = 0

    def collect(self) -> List[Dict[str, Union[str, int]]]:
        """
        Collects and returns metric data in a JSON-friendly format.

        Returns:
            List[Dict[str, Union[str, int]]]: A list of collected metrics.
        """
        with self.get_lock():
            collected_data = []
            for labels, value in self._values.items():
                label_dict = dict(zip(self._labels, labels))

                # labels descriptions
                label_descriptions = {
                    f"label_{i + 1}_des": label_des
                    for i, label_des in enumerate(self._labels_normalization.keys()) or {}
                }

                collected_data.append(
                    {
                        "name": self._full_name,
                        "value": value,
                        # Example: If labels=["service", "status"], and values=("sqs", "error"),
                        # it would generate: {"label_1": "sqs", "label_2": "error"}
                        **label_dict,
                        # Example: If labels=["service", "status"], it would generate:
                        # {"label_1_des": "service", "label_2_des": "status"}
                        **label_descriptions,
                    }
                )

            return collected_data

    def get_lock(self) -> threading.Lock:
        """Provides access to the internal lock."""
        return self._lock


class LabeledCounter:
    """
    A helper class that delegates label-specific operations to a `Counter`.

    - **Composition Pattern** → Holds a reference to `Counter` (`_counter`) and delegates operations.

    How to use:
        ```python
        # Create a counter with labels
        counter = Counter(namespace="api", name="http_requests", labels=["method"])

        # Get a delegate for a specific label
        label_delegate = counter.labels(method="GET")

        # Increment the labeled counter
        label_delegate.inc(5)  # Internally calls counter.inc(label_key=("GET",), value=5)

        # Reset the labeled counter
        label_delegate.reset()  # Internally calls counter.reset(label_key=("GET",))
        ```

    Attributes:
        _counter (Counter): Reference to the main counter.
        _labels (Tuple[Optional[str], ...]): The assigned label values.
    """

    _counter: Counter
    _labels: tuple[Optional[str], ...]

    def __init__(self, counter: Counter, labels: Tuple[Optional[str], ...]):
        self._counter = counter
        self._labels = labels

    def inc(self, value: int = 1) -> None:
        """
        Increments the labeled counter.

        Args:
            value (int): The amount to increment (must be positive).

        Raises:
            ValueError: If the increment value is not positive.
        """
        self._counter.inc(label_key=self._labels, value=value)

    def reset(self) -> None:
        """Resets the labeled counter to zero."""
        self._counter.reset(label_key=self._labels)


@hooks.on_infra_start()
def initialize_metric_registry() -> None:
    """
    Ensures the `CollectorRegistry` is instantiated as a Singleton.

    - This function is executed at infrastructure startup.
    - The same `CollectorRegistry` instance will be used globally.
    - All metrics (e.g., `Counter`, `Gauge`) will register themselves via `get_metric_registry()`.

    Returns:
        None
    """
    MetricRegistry()


@hooks.on_infra_shutdown()
def publish_metrics():
    """
    Collects all the registered metrics and immediately sends them to the analytics service.
    Skips execution if event tracking is disabled (`config.DISABLE_EVENTS`).

    This function is automatically triggered on infrastructure shutdown.
    """
    if config.DISABLE_EVENTS:
        return

    metadata = EventMetadata(
        session_id=get_session_id(),
        client_time=str(datetime.datetime.now()),
    )

    collected_metrics = get_metric_registry().collect()

    if collected_metrics:
        publisher = AnalyticsClientPublisher()
        publisher.publish([Event(name="ls_core", metadata=metadata, payload=collected_metrics)])
