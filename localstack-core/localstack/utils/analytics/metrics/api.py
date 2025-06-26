from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Protocol


class Payload(Protocol):
    def as_dict(self) -> dict[str, Any]: ...


class Metric(ABC):
    """
    Base class for all metrics (e.g., Counter, Gauge).
    Each subclass must implement the `collect()` method.
    """

    _namespace: str
    _name: str
    _schema_version: int

    def __init__(self, namespace: str, name: str, schema_version: int = 1):
        if not namespace or namespace.strip() == "":
            raise ValueError("Namespace must be non-empty string.")
        self._namespace = namespace

        if not name or name.strip() == "":
            raise ValueError("Metric name must be non-empty string.")
        self._name = name

        if schema_version is None:
            raise ValueError("An explicit schema_version is required for Counter metrics")

        if not isinstance(schema_version, int):
            raise TypeError("Schema version must be an integer.")

        if schema_version <= 0:
            raise ValueError("Schema version must be greater than zero.")

        self._schema_version = schema_version

    @property
    def namespace(self) -> str:
        return self._namespace

    @property
    def name(self) -> str:
        return self._name

    @property
    def schema_version(self) -> int:
        return self._schema_version

    @abstractmethod
    def collect(self) -> list[Payload]:
        """
        Collects and returns metric data. Subclasses must implement this to return collected metric data.
        """
        pass
