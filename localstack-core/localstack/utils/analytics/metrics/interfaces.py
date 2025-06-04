from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Union

from localstack.utils.analytics.metrics.counter import ThreadSafeCounter
from localstack.utils.analytics.metrics.types import CounterPayload


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


class CounterMetric(ABC):
    """
    Abstract base class for counter metrics.
    Defines the interface that all counter implementations must follow.
    """

    @abstractmethod
    def increment(self, value: int = 1) -> None:
        """Increment the counter by the specified value."""
        pass

    @abstractmethod
    def reset(self) -> None:
        """Reset the counter to zero."""
        pass

    @abstractmethod
    def collect(self) -> list[CounterPayload]:
        """Collect and return the current metric data."""
        pass

    @property
    @abstractmethod
    def count(self) -> int:
        """Get the current count value."""
        pass


class LabeledCounterMetric(ABC):
    """
    Abstract base class for labeled counter metrics.
    Defines the interface for counters that support labels.
    """

    @abstractmethod
    def collect(self) -> list[CounterPayload]:
        """Collect and return the current metric data."""
        pass

    @abstractmethod
    def labels(self, **kwargs: Union[str, float, None]) -> ThreadSafeCounter:
        """Get a counter instance for specific label values."""
        pass
