from dataclasses import dataclass
from typing import Any, Optional, Union


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
    schema_version: int
    labels: Optional[dict[str, Union[str, float]]] = None

    def as_dict(self) -> dict[str, Any]:
        result = {
            "namespace": self.namespace,
            "name": self.name,
            "value": self.value,
            "type": self.type,
            "schema_version": self.schema_version,
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
