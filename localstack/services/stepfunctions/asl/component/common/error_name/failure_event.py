from typing import Final, Optional

from localstack.aws.api.stepfunctions import ExecutionFailedEventDetails, HistoryEventType
from localstack.services.stepfunctions.asl.component.common.error_name.error_name import ErrorName
from localstack.services.stepfunctions.asl.eval.event.event_detail import EventDetails


class FailureEvent:
    error_name: Final[Optional[ErrorName]]
    event_type: Final[HistoryEventType]
    event_details: Final[Optional[EventDetails]]

    def __init__(
        self,
        error_name: Optional[ErrorName],
        event_type: HistoryEventType,
        event_details: Optional[EventDetails] = None,
    ):
        self.error_name = error_name
        self.event_type = event_type
        self.event_details = event_details


class FailureEventException(Exception):
    failure_event: Final[FailureEvent]

    def __init__(self, failure_event: FailureEvent):
        self.failure_event = failure_event

    def get_execution_failed_event_details(self) -> Optional[ExecutionFailedEventDetails]:
        if self.failure_event.event_details is None:
            return None

        failure_event_spec = list(self.failure_event.event_details.values())[0]

        execution_failed_event_details = ExecutionFailedEventDetails()
        if "error" in failure_event_spec:
            execution_failed_event_details["error"] = failure_event_spec["error"]
        if "cause" in failure_event_spec:
            execution_failed_event_details["cause"] = failure_event_spec["cause"]
        return execution_failed_event_details
