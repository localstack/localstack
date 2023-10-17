import copy
import datetime
import threading
from typing import Final, Optional

from localstack.aws.api.stepfunctions import (
    HistoryEvent,
    HistoryEventList,
    HistoryEventType,
    Timestamp,
)
from localstack.services.stepfunctions.asl.eval.event.event_detail import EventDetails


class EventHistory:
    _mutex: Final[threading.Lock]
    _history_event_list: Final[HistoryEventList]
    _id: int
    _prev_id: int

    def __init__(self):
        self._mutex = threading.Lock()
        self._history_event_list = list()
        self._id = 1
        self._prev_id = 0

    def add_event(
        self,
        hist_type_event: HistoryEventType,
        event_detail: Optional[EventDetails] = None,
        timestamp: Timestamp = None,
    ) -> None:
        with self._mutex:
            history_event = HistoryEvent()
            history_event["timestamp"] = timestamp or datetime.datetime.now()
            history_event["id"] = self._id
            history_event["previousEventId"] = self._prev_id
            history_event["type"] = hist_type_event
            if event_detail:
                history_event.update(event_detail)  # noqa

            self._id += 1
            self._prev_id += 1  # TODO: implement previousEventId behaviour.

            self._history_event_list.append(history_event)

    def get_event_history(self) -> HistoryEventList:
        with self._mutex:
            return copy.deepcopy(self._history_event_list)
