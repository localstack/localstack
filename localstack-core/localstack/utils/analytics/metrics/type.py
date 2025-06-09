from dataclasses import dataclass
from typing import Any, Union


@dataclass(frozen=True)
class MetricRegistryKey:
    """A unique identifier for a metric, composed of namespace and name."""

    namespace: str
    name: str


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
    labels: dict[str, Union[str, float]]
    schema_version: int

    def as_dict(self) -> dict[str, Any]:
        dict = {
            "namespace": self.namespace,
            "name": self.name,
            "value": self.value,
            "type": self.type,
            "schema_version": self.schema_version,
        }

        for i, (label_name, label_value) in enumerate(self.labels.items(), 1):
            dict[f"label_{i}"] = label_name
            dict[f"label_{i}_value"] = label_value

        return dict


@dataclass
class MetricPayload:
    """
    A data object storing the value of all metrics collected during the execution of the application.
    """

    _payload: list[Union[CounterPayload, LabeledCounterPayload]]

    @property
    def payload(self) -> list[Union[CounterPayload, LabeledCounterPayload]]:
        return self._payload

    def __init__(self, payload: list[Union[CounterPayload, LabeledCounterPayload]]):
        self._payload = payload

    def as_dict(self) -> dict[str, list[dict[str, Any]]]:
        return {"metrics": [payload.as_dict() for payload in self._payload]}
