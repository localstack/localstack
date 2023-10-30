from __future__ import annotations

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


class EventHistoryContext:
    # The '0' event is the source event id of the program execution.
    _PROGRAM_START_EVENT_ID: Final[int] = 0

    source_event_id: int
    last_published_event_id: int

    def __init__(self, previous_event_id: int):
        self.source_event_id = previous_event_id
        self.last_published_event_id = previous_event_id

    @classmethod
    def of_program_start(cls) -> EventHistoryContext:
        return cls(previous_event_id=cls._PROGRAM_START_EVENT_ID)

    def integrate(self, other: EventHistoryContext) -> None:
        self.source_event_id = max(self.source_event_id, other.source_event_id)
        self.last_published_event_id = max(
            self.last_published_event_id, other.last_published_event_id
        )


class EventIdGenerator:
    _next_id: int

    def __init__(self):
        self._next_id = 1

    def get(self) -> int:
        next_id = self._next_id
        self._next_id += 1
        return next_id


class EventHistory:
    _mutex: Final[threading.Lock]
    _history_event_list: Final[HistoryEventList]
    _event_id_gen: EventIdGenerator

    def __init__(self):
        self._mutex = threading.Lock()
        self._history_event_list = list()
        self._event_id_gen = EventIdGenerator()

    def add_event(
        self,
        context: EventHistoryContext,
        hist_type_event: HistoryEventType,
        event_detail: Optional[EventDetails] = None,
        timestamp: Timestamp = None,
        update_source_event_id: bool = True,
    ) -> int:
        with self._mutex:
            event_id: int = self._event_id_gen.get()
            history_event = HistoryEvent()
            if event_detail:
                history_event.update(event_detail)
            history_event["id"] = event_id
            history_event["previousEventId"] = context.source_event_id
            history_event["type"] = hist_type_event
            history_event["timestamp"] = timestamp or datetime.datetime.now()
            self._history_event_list.append(history_event)
            context.last_published_event_id = event_id
            if update_source_event_id:
                context.source_event_id = event_id
            return event_id

    def get_event_history(self) -> HistoryEventList:
        with self._mutex:
            return copy.deepcopy(self._history_event_list)
