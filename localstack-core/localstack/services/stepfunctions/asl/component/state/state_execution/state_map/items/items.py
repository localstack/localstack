import abc
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
from localstack.services.stepfunctions.asl.component.common.jsonata.jsonata_template_value_array import (
    JSONataTemplateValueArray,
)
from localstack.services.stepfunctions.asl.component.common.string.string_expression import (
    StringJSONata,
)
from localstack.services.stepfunctions.asl.component.eval_component import EvalComponent
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.services.stepfunctions.asl.eval.event.event_detail import EventDetails
from localstack.services.stepfunctions.asl.utils.encoding import to_json_str


class Items(EvalComponent, abc.ABC): ...


class ItemsArray(Items):
    jsonata_template_value_array: Final[JSONataTemplateValueArray]

    def __init__(self, jsonata_template_value_array: JSONataTemplateValueArray):
        super().__init__()
        self.jsonata_template_value_array = jsonata_template_value_array

    def _eval_body(self, env: Environment) -> None:
        self.jsonata_template_value_array.eval(env=env)


class ItemsJSONata(Items):
    string_jsonata: Final[StringJSONata]

    def __init__(self, string_jsonata: StringJSONata):
        self.string_jsonata = string_jsonata

    def _eval_body(self, env: Environment) -> None:
        self.string_jsonata.eval(env=env)
        items = env.stack[-1]
        if not isinstance(items, list):
            # FIXME: If we pass in a 'function' type, the JSONata lib will return a dict and the
            # 'unsupported result type state' wont be reached.
            def _get_jsonata_value_type_pair(items) -> tuple[str, str]:
                match items:
                    case None:
                        return "null", "null"
                    case int() | float():
                        if isinstance(items, bool):
                            return "true" if items else "false", "boolean"
                        return items, "number"
                    case str():
                        return f'"{items}"', "string"
                    case dict():
                        return to_json_str(items, separators=(",", ":")), "object"

            expr = self.string_jsonata.literal_value
            if jsonata_pair := _get_jsonata_value_type_pair(items):
                jsonata_value, jsonata_type = jsonata_pair
                error_cause = (
                    f"The JSONata expression '{expr}' specified for the field 'Items' returned an unexpected result type. "
                    f"Expected 'array', but was '{jsonata_type}' for value: {jsonata_value}"
                )
            else:
                error_cause = f"The JSONata expression '{expr}' for the field 'Items' returned an unsupported result type."

            error_name = StatesErrorName(typ=StatesErrorNameType.StatesQueryEvaluationError)
            failure_event = FailureEvent(
                env=env,
                error_name=error_name,
                event_type=HistoryEventType.EvaluationFailed,
                event_details=EventDetails(
                    evaluationFailedEventDetails=EvaluationFailedEventDetails(
                        error=error_name.error_name, cause=error_cause, location="Items"
                    )
                ),
            )
            raise FailureEventException(failure_event=failure_event)
