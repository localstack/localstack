import datetime

from .events import Event, EventHandler, EventMetadata, EventPayload
from .metadata import get_client_metadata, get_session_id


def get_hash(value) -> str:
    # FIXME: seems a bit hacky

    if value is None:
        return "0"

    max_hash = 10000000000
    hashed = hash(str(value)) % max_hash
    hashed = hex(hashed).replace("0x", "")
    return hashed


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

    def infra_start(self):
        self._log("infra_start", payload=get_client_metadata())

    def infra_stop(self):
        self._log("infra_stop", payload=get_client_metadata())

    def _log(self, event: str, payload: EventPayload = None):
        self.handler.handle(Event(metadata=self._metadata(event), payload=payload))

    def _metadata(self, event: str) -> EventMetadata:
        return EventMetadata(
            session_id=self.session_id,
            client_time=str(datetime.datetime.now()),
            event=event,
        )
