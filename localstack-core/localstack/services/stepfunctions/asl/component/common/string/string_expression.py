import abc
import copy
from typing import Any, Final, Optional

from localstack.aws.api.stepfunctions import HistoryEventType, TaskFailedEventDetails
from localstack.services.events.utils import to_json_str
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
from localstack.services.stepfunctions.asl.component.common.query_language import QueryLanguageMode
from localstack.services.stepfunctions.asl.component.eval_component import EvalComponent
from localstack.services.stepfunctions.asl.component.intrinsic.jsonata import (
    get_intrinsic_functions_declarations,
)
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.services.stepfunctions.asl.eval.event.event_detail import EventDetails
from localstack.services.stepfunctions.asl.jsonata.jsonata import (
    JSONataExpression,
    VariableDeclarations,
    VariableReference,
    compose_jsonata_expression,
    eval_jsonata_expression,
    extract_jsonata_variable_references,
)
from localstack.services.stepfunctions.asl.jsonata.validations import (
    validate_jsonata_expression_output,
)
from localstack.services.stepfunctions.asl.utils.json_path import (
    NoSuchJsonPathError,
    extract_json,
)

JSONPATH_ROOT_PATH: Final[str] = "$"


class StringExpression(EvalComponent, abc.ABC):
    literal_value: Final[str]

    def __init__(self, literal_value: str):
        self.literal_value = literal_value

    def _field_name(self) -> Optional[str]:
        return None


class StringExpressionSimple(StringExpression, abc.ABC): ...


class StringSampler(StringExpressionSimple, abc.ABC): ...


class StringLiteral(StringExpression):
    def _eval_body(self, env: Environment) -> None:
        env.stack.append(self.literal_value)


class StringJsonPath(StringSampler):
    json_path: Final[str]

    def __init__(self, json_path: str):
        super().__init__(literal_value=json_path)
        self.json_path = json_path

    def _eval_body(self, env: Environment) -> None:
        input_value: Any = env.stack[-1]
        if self.json_path == JSONPATH_ROOT_PATH:
            output_value = input_value
        else:
            output_value = extract_json(self.json_path, input_value)
        # TODO: introduce copy on write approach
        env.stack.append(copy.deepcopy(output_value))


class StringContextPath(StringJsonPath):
    context_object_path: Final[str]

    def __init__(self, context_object_path: str):
        json_path = context_object_path[1:]
        super().__init__(json_path=json_path)
        self.context_object_path = context_object_path

    def _eval_body(self, env: Environment) -> None:
        input_value = env.states.context_object.context_object_data
        if self.json_path == JSONPATH_ROOT_PATH:
            output_value = input_value
        else:
            try:
                output_value = extract_json(self.json_path, input_value)
            except NoSuchJsonPathError:
                input_value_json_str = to_json_str(input_value)
                cause = (
                    f"The JSONPath '${self.json_path}' specified for the field '{env.next_field_name}' "
                    f"could not be found in the input '{input_value_json_str}'"
                )
                raise FailureEventException(
                    failure_event=FailureEvent(
                        env=env,
                        error_name=StatesErrorName(typ=StatesErrorNameType.StatesRuntime),
                        event_type=HistoryEventType.TaskFailed,
                        event_details=EventDetails(
                            taskFailedEventDetails=TaskFailedEventDetails(
                                error=StatesErrorNameType.StatesRuntime.to_name(), cause=cause
                            )
                        ),
                    )
                )
        # TODO: introduce copy on write approach
        env.stack.append(copy.deepcopy(output_value))


class StringVariableSample(StringSampler):
    query_language_mode: Final[QueryLanguageMode]
    expression: Final[str]

    def __init__(self, query_language_mode: QueryLanguageMode, expression: str):
        super().__init__(literal_value=expression)
        self.query_language_mode = query_language_mode
        self.expression = expression

    def _eval_body(self, env: Environment) -> None:
        # Get the variables sampled in the jsonata expression.
        expression_variable_references: set[VariableReference] = (
            extract_jsonata_variable_references(self.expression)
        )
        variable_declarations_list = list()
        if self.query_language_mode == QueryLanguageMode.JSONata:
            # Sample $states values into expression.
            states_variable_declarations: VariableDeclarations = (
                env.states.to_variable_declarations(
                    variable_references=expression_variable_references
                )
            )
            variable_declarations_list.append(states_variable_declarations)

        # Sample Variable store values in to expression.
        # TODO: this could be optimised by sampling only those invoked.
        variable_declarations: VariableDeclarations = env.variable_store.get_variable_declarations()
        variable_declarations_list.append(variable_declarations)

        rich_jsonata_expression: JSONataExpression = compose_jsonata_expression(
            final_jsonata_expression=self.expression,
            variable_declarations_list=variable_declarations_list,
        )
        result = eval_jsonata_expression(rich_jsonata_expression)
        env.stack.append(result)


class StringIntrinsicFunction(StringExpressionSimple):
    intrinsic_function_derivation: Final[str]
    function: Final[EvalComponent]

    def __init__(self, intrinsic_function_derivation: str, function: EvalComponent) -> None:
        super().__init__(literal_value=intrinsic_function_derivation)
        self.intrinsic_function_derivation = intrinsic_function_derivation
        self.function = function

    def _eval_body(self, env: Environment) -> None:
        self.function.eval(env=env)


class StringJSONata(StringExpression):
    expression: Final[str]

    def __init__(self, expression: str):
        super().__init__(literal_value=expression)
        # TODO: check for illegal functions ($, $$, $eval)
        self.expression = expression

    def _eval_body(self, env: Environment) -> None:
        # Get the variables sampled in the jsonata expression.
        expression_variable_references: set[VariableReference] = (
            extract_jsonata_variable_references(self.expression)
        )

        # Sample declarations for used intrinsic functions. Place this at the start allowing users to
        # override these identifiers with custom variable declarations.
        functions_variable_declarations: VariableDeclarations = (
            get_intrinsic_functions_declarations(variable_references=expression_variable_references)
        )

        # Sample $states values into expression.
        states_variable_declarations: VariableDeclarations = env.states.to_variable_declarations(
            variable_references=expression_variable_references
        )

        # Sample Variable store values in to expression.
        # TODO: this could be optimised by sampling only those invoked.
        variable_declarations: VariableDeclarations = env.variable_store.get_variable_declarations()

        rich_jsonata_expression: JSONataExpression = compose_jsonata_expression(
            final_jsonata_expression=self.expression,
            variable_declarations_list=[
                functions_variable_declarations,
                states_variable_declarations,
                variable_declarations,
            ],
        )
        result = eval_jsonata_expression(rich_jsonata_expression)

        validate_jsonata_expression_output(env, self.expression, rich_jsonata_expression, result)

        env.stack.append(result)
