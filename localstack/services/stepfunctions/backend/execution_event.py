from typing import Optional

from localstack.aws.api.stepfunctions import (
    EventId,
    ExecutionSucceededEventDetails,
    HistoryEvent,
    HistoryEventType,
    Timestamp,
)


# TODO: missing fields.
class ExecutionEvent:
    def __init__(self, timestamp: Timestamp, event_type: HistoryEventType, event_id: EventId = -1):
        self.timestamp: Timestamp = timestamp
        self.event_type: HistoryEventType = event_type
        self.event_id: EventId = event_id
        self.execution_succeeded_event_details: Optional[ExecutionSucceededEventDetails] = None

    def to_history_event(self) -> HistoryEvent:
        event = HistoryEvent(
            timestamp=self.timestamp,
            type=self.event_type,
            id=self.event_id,
        )
        if self.execution_succeeded_event_details:
            event["executionSucceededEventDetails"] = self.execution_succeeded_event_details
        return event
