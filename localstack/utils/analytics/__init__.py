from .logger import EventLogger
from .metadata import get_session_id
from .publisher import GlobalAnalyticsBus
from .usage import UsageEventHandler, UsageLogger

name = "analytics"


def _create_global_analytics_bus():
    return GlobalAnalyticsBus()


log = EventLogger(handler=_create_global_analytics_bus(), session_id=get_session_id())

# our own "GlobalAnalyticsBus"
usage_event_handler = UsageEventHandler()
usage_log = UsageLogger(handler=usage_event_handler)
