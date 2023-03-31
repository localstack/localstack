from typing import Final

from localstack.aws.api.stepfunctions import HistoryEventType
from localstack.services.stepfunctions.asl.component.common.error_name.error_name import ErrorName
from localstack.services.stepfunctions.asl.eval.event.event_detail import EventDetails


class FailureEvent:
    error_name: Final[ErrorName]
    event_type: Final[HistoryEventType]
    event_details: Final[EventDetails]

    def __init__(
        self, error_name: ErrorName, event_type: HistoryEventType, event_details: EventDetails
    ):
        self.error_name = error_name
        self.event_type = event_type
        self.event_details = event_details
