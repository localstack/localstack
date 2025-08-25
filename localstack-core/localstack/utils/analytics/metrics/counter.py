import threading
from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Optional, Union

from localstack import config

from .api import Metric
from .registry import MetricRegistry


@dataclass(frozen=True)
class CounterPayload:
    """A data object storing the value of a Counter metric."""

    namespace: str
    name: str
    value: int
    type: str
    schema_version: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "namespace": self.namespace,
            "name": self.name,
            "value": self.value,
            "type": self.type,
            "schema_version": self.schema_version,
        }


@dataclass(frozen=True)
class LabeledCounterPayload:
    """A data object storing the value of a LabeledCounter metric."""

    namespace: str
    name: str
    value: int
    type: str
    schema_version: int
    labels: dict[str, Union[str, float]]

    def as_dict(self) -> dict[str, Any]:
        payload_dict = {
            "namespace": self.namespace,
            "name": self.name,
            "value": self.value,
            "type": self.type,
            "schema_version": self.schema_version,
        }

        for i, (label_name, label_value) in enumerate(self.labels.items(), 1):
            payload_dict[f"label_{i}"] = label_name
            payload_dict[f"label_{i}_value"] = label_value

        return payload_dict


class ThreadSafeCounter:
    """
    A thread-safe counter for any kind of tracking.
    This class should not be instantiated directly, use Counter or LabeledCounter  instead.
    """

    _mutex: threading.Lock
    _count: int

    def __init__(self):
        super().__init__()
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


class Counter(Metric, ThreadSafeCounter):
    """
    A thread-safe, unlabeled counter for tracking the total number of occurrences of a specific event.
    This class is intended for metrics that do not require differentiation across dimensions.
    For use cases where metrics need to be grouped or segmented by labels, use `LabeledCounter` instead.
    """

    _type: str

    def __init__(self, namespace: str, name: str, schema_version: int = 1):
        Metric.__init__(self, namespace=namespace, name=name, schema_version=schema_version)
        ThreadSafeCounter.__init__(self)

        self._type = "counter"
        MetricRegistry().register(self)

    def collect(self) -> list[CounterPayload]:
        """Collects the metric unless events are disabled."""
        if config.DISABLE_EVENTS:
            return []

        if self._count == 0:
            # Return an empty list if the count is 0, as there are no metrics to send to the analytics backend.
            return []

        return [
            CounterPayload(
                namespace=self._namespace,
                name=self.name,
                value=self._count,
                type=self._type,
                schema_version=self._schema_version,
            )
        ]


class LabeledCounter(Metric):
    """
    A thread-safe counter for tracking occurrences of an event across multiple combinations of label values.
    It enables fine-grained metric collection and analysis, with each unique label set stored and counted independently.
    Use this class when you need dimensional insights into event occurrences.
    For simpler, unlabeled use cases, see the `Counter` class.
    """

    _type: str
    _labels: list[str]
    _label_values: tuple[Optional[Union[str, float]], ...]
    _counters_by_label_values: defaultdict[
        tuple[Optional[Union[str, float]], ...], ThreadSafeCounter
    ]

    def __init__(self, namespace: str, name: str, labels: list[str], schema_version: int = 1):
        super().__init__(namespace=namespace, name=name, schema_version=schema_version)

        if not labels:
            raise ValueError("At least one label is required; the labels list cannot be empty.")

        if any(not label for label in labels):
            raise ValueError("Labels must be non-empty strings.")

        if len(labels) > 6:
            raise ValueError("Too many labels: counters allow a maximum of 6.")

        self._type = "counter"
        self._labels = labels
        self._counters_by_label_values = defaultdict(ThreadSafeCounter)
        MetricRegistry().register(self)

    def labels(self, **kwargs: Union[str, float, None]) -> ThreadSafeCounter:
        """
        Create a scoped counter instance with specific label values.

        This method assigns values to the predefined labels of a labeled counter and returns
        a ThreadSafeCounter object that allows tracking metrics for that specific
        combination of label values.

        :raises ValueError:
            - If the set of keys provided labels does not match the expected set of labels.
        """
        if set(self._labels) != set(kwargs.keys()):
            raise ValueError(f"Expected labels {self._labels}, got {list(kwargs.keys())}")

        _label_values = tuple(kwargs[label] for label in self._labels)

        return self._counters_by_label_values[_label_values]

    def collect(self) -> list[LabeledCounterPayload]:
        if config.DISABLE_EVENTS:
            return []

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
            labels_dict = dict(zip(self._labels, label_values))

            payload.append(
                LabeledCounterPayload(
                    namespace=self._namespace,
                    name=self.name,
                    value=counter.count,
                    type=self._type,
                    schema_version=self._schema_version,
                    labels=labels_dict,
                )
            )

        return payload
