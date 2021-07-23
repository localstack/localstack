import abc
import dataclasses
from typing import Any, Dict, Union

EventPayload = Union[Dict[str, Any], Any]  # FIXME: better typing


@dataclasses.dataclass
class EventMetadata:
    session_id: str
    client_time: str
    event: str


@dataclasses.dataclass
class Event:
    metadata: EventMetadata
    payload: EventPayload

    def asdict(self):
        return dataclasses.asdict(self)


class EventHandler(abc.ABC):
    """
    Event handlers dispatch events to specific destinations.
    """

    def handle(self, event: Event):
        raise NotImplementedError
