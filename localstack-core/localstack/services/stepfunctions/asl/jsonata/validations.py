from typing import Final

from localstack.aws.api.stepfunctions import (
    EvaluationFailedEventDetails,
    HistoryEventType,
)
from localstack.services.stepfunctions.asl.component.common.error_name.failure_event import (
    FailureEvent,
    FailureEventException,
)
from localstack.services.stepfunctions.asl.component.common.error_name.states_error_name import (
    StatesErrorName,
)
from localstack.services.stepfunctions.asl.component.common.error_name.states_error_name_type import (
    StatesErrorNameType,
)
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.services.stepfunctions.asl.eval.event.event_detail import EventDetails
from localstack.services.stepfunctions.asl.jsonata.jsonata import (
    eval_jsonata_expression,
)

_SUPPORTED_JSONATA_TYPES: Final[set[str]] = {
    "null",
    "number",
    "string",
    "boolean",
    "array",
    "object",
}


def _validate_null_output(env: Environment, expression: str, rich_jsonata_expression: str) -> None:
    exists: bool = eval_jsonata_expression(f"$exists({rich_jsonata_expression})")
    if exists:
        return
    error_name = StatesErrorName(typ=StatesErrorNameType.StatesQueryEvaluationError)
    failure_event = FailureEvent(
        env=env,
        error_name=error_name,
        event_type=HistoryEventType.EvaluationFailed,
        event_details=EventDetails(
            evaluationFailedEventDetails=EvaluationFailedEventDetails(
                # TODO: Add snapshot test to investigate behaviour for field string
                cause=f"The JSONata expression '{expression}' returned nothing (undefined).",
                error=error_name.error_name,
            )
        ),
    )
    raise FailureEventException(failure_event=failure_event)


def _validate_string_output(
    env: Environment, expression: str, rich_jsonata_expression: str
) -> None:
    jsonata_type: str = eval_jsonata_expression(f"$type({rich_jsonata_expression})")
    if jsonata_type in _SUPPORTED_JSONATA_TYPES:
        return
    error_name = StatesErrorName(typ=StatesErrorNameType.StatesQueryEvaluationError)
    failure_event = FailureEvent(
        env=env,
        error_name=error_name,
        event_type=HistoryEventType.EvaluationFailed,
        event_details=EventDetails(
            evaluationFailedEventDetails=EvaluationFailedEventDetails(
                # TODO: Add snapshot test to investigate behaviour for field string
                cause=f"The JSONata expression '{expression}' returned an unsupported result type.",
                error=error_name.error_name,
            )
        ),
    )
    raise FailureEventException(failure_event=failure_event)


def validate_jsonata_expression_output(
    env: Environment, expression: str, rich_jsonata_expression: str, jsonata_result: str
) -> None:
    try:
        if jsonata_result is None:
            _validate_null_output(env, expression, rich_jsonata_expression)
        if isinstance(jsonata_result, str):
            _validate_string_output(env, expression, rich_jsonata_expression)
    except FailureEventException as ex:
        env.event_manager.add_event(
            context=env.event_history_context,
            event_type=HistoryEventType.EvaluationFailed,
            event_details=EventDetails(
                evaluationFailedEventDetails=ex.get_evaluation_failed_event_details()
            ),
        )
        raise ex
