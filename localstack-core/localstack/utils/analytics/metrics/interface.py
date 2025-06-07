from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Union

from .type import CounterPayload, LabeledCounterPayload


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
    def collect(self) -> list[Union[CounterPayload, LabeledCounterPayload]]:
        """
        Collects and returns metric data. Subclasses must implement this to return collected metric data.
        """
        pass
