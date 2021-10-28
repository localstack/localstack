import datetime
import hashlib

from ..common import to_bytes
from .events import Event, EventHandler, EventMetadata, EventPayload
from .metadata import get_session_id


def get_hash(value) -> str:
    max_length = 10
    digest = hashlib.sha1()
    digest.update(to_bytes(str(value)))
    result = digest.hexdigest()
    return result[:max_length]


class EventLogger:
    """
    High-level interface over analytics event abstraction. Expose specific event types as
    concrete functions to call in the code.
    """

    def __init__(self, handler: EventHandler, session_id: str = None):
        self.handler = handler
        self.session_id = session_id or get_session_id()

    @staticmethod
    def hash(value):
        return get_hash(value)

    def event(self, event: str, payload: EventPayload = None, **kwargs):
        if kwargs:
            if payload is None:
                payload = kwargs
            else:
                raise ValueError("either use payload or set kwargs, not both")

        self._log(event, payload=payload)

    def _log(self, event: str, payload: EventPayload = None):
        self.handler.handle(Event(name=event, metadata=self._metadata(), payload=payload))

    def _metadata(self) -> EventMetadata:
        return EventMetadata(
            session_id=self.session_id,
            client_time=str(datetime.datetime.now()),
        )
