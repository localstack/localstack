from typing import Final, Optional

from localstack.aws.api.stepfunctions import ExecutionFailedEventDetails, HistoryEventType
from localstack.services.stepfunctions.asl.component.common.error_name.error_name import ErrorName
from localstack.services.stepfunctions.asl.component.common.error_name.states_error_name_type import (
    StatesErrorNameType,
)
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.services.stepfunctions.asl.eval.event.event_detail import EventDetails


class FailureEvent:
    state_name: Final[str]
    source_event_id: Final[int]
    error_name: Final[Optional[ErrorName]]
    event_type: Final[HistoryEventType]
    event_details: Final[Optional[EventDetails]]

    def __init__(
        self,
        env: Environment,
        error_name: Optional[ErrorName],
        event_type: HistoryEventType,
        event_details: Optional[EventDetails] = None,
    ):
        self.state_name = env.next_state_name
        self.source_event_id = env.event_history_context.source_event_id
        self.error_name = error_name
        self.event_type = event_type
        self.event_details = event_details


class FailureEventException(Exception):
    failure_event: Final[FailureEvent]

    def __init__(self, failure_event: FailureEvent):
        self.failure_event = failure_event

    def extract_error_cause_pair(self) -> Optional[tuple[Optional[str], Optional[str]]]:
        if self.failure_event.event_details is None:
            return None

        failure_event_spec = list(self.failure_event.event_details.values())[0]

        error = None
        cause = None
        if "error" in failure_event_spec:
            error = failure_event_spec["error"]
        if "cause" in failure_event_spec:
            cause = failure_event_spec["cause"]
        return error, cause

    def get_execution_failed_event_details(self) -> Optional[ExecutionFailedEventDetails]:
        maybe_error_cause_pair = self.extract_error_cause_pair()
        if maybe_error_cause_pair is None:
            return None
        execution_failed_event_details = ExecutionFailedEventDetails()
        error, cause = maybe_error_cause_pair
        if error:
            execution_failed_event_details["error"] = error
        if cause:
            if error == StatesErrorNameType.StatesRuntime.to_name():
                state_name = self.failure_event.state_name
                event_id = self.failure_event.source_event_id
                decorated_cause = f"An error occurred while executing the state '{state_name}' (entered at the event id #{event_id}). {cause}"
                execution_failed_event_details["cause"] = decorated_cause
            else:
                execution_failed_event_details["cause"] = cause

        return execution_failed_event_details
