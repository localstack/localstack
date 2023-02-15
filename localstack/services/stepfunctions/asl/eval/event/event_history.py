import copy
import datetime
from typing import Final

from localstack.aws.api.stepfunctions import (
    HistoryEvent,
    HistoryEventList,
    HistoryEventType,
    Timestamp,
)
from localstack.services.stepfunctions.asl.eval.event.event_detail import EventDetails


class EventHistory:
    def __init__(self):
        self._history_event_list: Final[HistoryEventList] = list()
        self._id = 1
        self._prev_id = 0  # TODO: implement previousEventId behaviour.

    def add_event(
        self,
        hist_type_event: HistoryEventType,
        event_detail: EventDetails,
        timestamp: Timestamp = None,
    ) -> None:
        history_event = HistoryEvent()
        history_event["id"] = self._id
        history_event["previousEventId"] = self._prev_id
        history_event["type"] = hist_type_event
        history_event["timestamp"] = timestamp or datetime.datetime.now()
        history_event.update(event_detail)  # noqa

        self._id += 1
        self._prev_id += 1  # TODO: implement previousEventId behaviour.

        self._history_event_list.append(history_event)

    def get_event_history(self) -> HistoryEventList:
        return copy.deepcopy(self._history_event_list)
