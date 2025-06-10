from __future__ import annotations

import logging
import threading
from dataclasses import dataclass
from typing import Any

from .api import Metric, Payload

LOG = logging.getLogger(__name__)


@dataclass
class MetricPayload:
    """
    A data object storing the value of all metrics collected during the execution of the application.
    """

    _payload: list[Payload]

    @property
    def payload(self) -> list[Payload]:
        return self._payload

    def __init__(self, payload: list[Payload]):
        self._payload = payload

    def as_dict(self) -> dict[str, list[dict[str, Any]]]:
        return {"metrics": [payload.as_dict() for payload in self._payload]}


@dataclass(frozen=True)
class MetricRegistryKey:
    """A unique identifier for a metric, composed of namespace and name."""

    namespace: str
    name: str


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
    def registry(self) -> dict[MetricRegistryKey, Metric]:
        return self._registry

    def register(self, metric: Metric) -> None:
        """
        Registers a metric instance.

        Raises a TypeError if the object is not a Metric,
        or a ValueError if a metric with the same namespace and name is already registered
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
