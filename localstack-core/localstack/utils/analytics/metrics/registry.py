from __future__ import annotations

import logging
import threading

from .interfaces import Metric
from .types import MetricPayload, MetricRegistryKey

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
    def registry(self) -> dict[MetricRegistryKey, Metric]:
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
