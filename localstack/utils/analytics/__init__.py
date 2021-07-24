from .events import Event, EventHandler
from .logger import EventLogger
from .metadata import get_session_id
from .publisher import publish

name = "analytics"


class _EventPublisher(EventHandler):
    def handle(self, event: Event):
        publish(event)


log = EventLogger(handler=_EventPublisher(), session_id=get_session_id())
