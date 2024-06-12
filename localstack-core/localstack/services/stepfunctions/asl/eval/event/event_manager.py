from __future__ import annotations

import copy
import datetime
import logging
import threading
from typing import Final, Optional

from localstack.aws.api.stepfunctions import (
    HistoryEvent,
    HistoryEventList,
    HistoryEventType,
    LongArn,
    Timestamp,
)
from localstack.services.stepfunctions.asl.eval.event.event_detail import EventDetails
from localstack.services.stepfunctions.asl.eval.event.logging import (
    CloudWatchLoggingSession,
    HistoryLog,
)
from localstack.services.stepfunctions.asl.utils.encoding import to_json_str

LOG = logging.getLogger(__name__)


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


class EventManager:
    _mutex: Final[threading.Lock]
    _event_id_gen: EventIdGenerator
    _history_event_list: Final[HistoryEventList]
    _cloud_watch_logging_session: Final[Optional[CloudWatchLoggingSession]]

    def __init__(self, cloud_watch_logging_session: Optional[CloudWatchLoggingSession] = None):
        self._mutex = threading.Lock()
        self._event_id_gen = EventIdGenerator()
        self._history_event_list = list()
        self._cloud_watch_logging_session = cloud_watch_logging_session

    def add_event(
        self,
        context: EventHistoryContext,
        event_type: HistoryEventType,
        event_details: Optional[EventDetails] = None,
        timestamp: Timestamp = None,
        update_source_event_id: bool = True,
    ) -> int:
        with self._mutex:
            event_id: int = self._event_id_gen.get()
            source_event_id: int = context.source_event_id
            timestamp = timestamp or self._get_current_timestamp()

            context.last_published_event_id = event_id
            if update_source_event_id:
                context.source_event_id = event_id

            self._publish_history_event(
                event_id=event_id,
                source_event_id=source_event_id,
                event_type=event_type,
                timestamp=timestamp,
                event_details=event_details,
            )
            self._publish_history_log(
                event_id=event_id,
                source_event_id=source_event_id,
                event_type=event_type,
                timestamp=timestamp,
                event_details=event_details,
            )

            return event_id

    @staticmethod
    def _get_current_timestamp() -> datetime.datetime:
        return datetime.datetime.now(tz=datetime.timezone.utc)

    @staticmethod
    def _create_history_event(
        event_id: int,
        source_event_id: int,
        event_type: HistoryEventType,
        timestamp: datetime.datetime,
        event_details: Optional[EventDetails],
    ) -> HistoryEvent:
        history_event = HistoryEvent()
        if event_details is not None:
            history_event.update(event_details)
        history_event["id"] = event_id
        history_event["previousEventId"] = source_event_id
        history_event["type"] = event_type
        history_event["timestamp"] = timestamp
        return history_event

    def _publish_history_event(
        self,
        event_id: int,
        source_event_id: int,
        event_type: HistoryEventType,
        timestamp: datetime.datetime,
        event_details: Optional[EventDetails],
    ):
        history_event = self._create_history_event(
            event_id=event_id,
            source_event_id=source_event_id,
            event_type=event_type,
            timestamp=timestamp,
            event_details=event_details,
        )
        self._history_event_list.append(history_event)

    @staticmethod
    def _remove_data_from_history_log(details_body: dict) -> None:
        remove_keys = ["input", "inputDetails", "output", "outputDetails"]
        for remove_key in remove_keys:
            details_body.pop(remove_key, None)

    @staticmethod
    def _create_history_log(
        event_id: int,
        source_event_id: int,
        event_type: HistoryEventType,
        timestamp: datetime.datetime,
        execution_arn: LongArn,
        event_details: Optional[EventDetails],
        include_execution_data: bool,
    ) -> HistoryLog:
        log = HistoryLog(
            id=str(event_id),
            previous_event_id=str(source_event_id),
            event_timestamp=timestamp,
            type=event_type,
            execution_arn=execution_arn,
        )
        if event_details:
            if len(event_details) > 1:
                LOG.warning(f"Event details with multiple bindings: {to_json_str(event_details)}")
            details_body = next(iter(event_details.values()))
            if not include_execution_data:
                # clone the object before modifying it as the change is limited to the history log value.
                details_body = copy.deepcopy(details_body)
                EventManager._remove_data_from_history_log(details_body=details_body)
            log["details"] = details_body
        return log

    def _publish_history_log(
        self,
        event_id: int,
        source_event_id: int,
        event_type: HistoryEventType,
        timestamp: datetime.datetime,
        event_details: Optional[EventDetails],
    ):
        # No logging session for this execution.
        if self._cloud_watch_logging_session is None:
            return

        # This event is not recorded by this execution's logging configuration.
        if not self._cloud_watch_logging_session.log_level_filter(history_event_type=event_type):
            return

        history_log = self._create_history_log(
            event_id=event_id,
            source_event_id=source_event_id,
            event_type=event_type,
            timestamp=timestamp,
            execution_arn=self._cloud_watch_logging_session.execution_arn,
            event_details=event_details,
            include_execution_data=self._cloud_watch_logging_session.configuration.include_execution_data,
        )
        self._cloud_watch_logging_session.publish_history_log(history_log=history_log)

    def get_event_history(self) -> HistoryEventList:
        with self._mutex:
            return copy.deepcopy(self._history_event_list)
