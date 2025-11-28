import enum
from typing import Final

from antlr4.tree.Tree import ParseTree

from localstack.services.stepfunctions.asl.antlr.runtime.ASLParser import ASLParser
from localstack.services.stepfunctions.asl.antlt4utils.antlr4utils import (
    is_production,
)
from localstack.services.stepfunctions.asl.component.common.parargs import (
    ArgumentsJSONataTemplateValueObject,
    ArgumentsStringJSONata,
    Parameters,
)
from localstack.services.stepfunctions.asl.component.common.path.input_path import InputPath
from localstack.services.stepfunctions.asl.component.common.path.items_path import ItemsPath
from localstack.services.stepfunctions.asl.component.common.path.result_path import ResultPath
from localstack.services.stepfunctions.asl.component.common.query_language import QueryLanguage
from localstack.services.stepfunctions.asl.component.common.result_selector import ResultSelector
from localstack.services.stepfunctions.asl.component.state.state import CommonStateField
from localstack.services.stepfunctions.asl.component.state.state_choice.state_choice import (
    StateChoice,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.max_concurrency import (
    MaxConcurrency,
    MaxConcurrencyJSONata,
    MaxConcurrencyPath,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.state_map import (
    StateMap,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.tolerated_failure import (
    ToleratedFailureCountInt,
    ToleratedFailureCountPath,
    ToleratedFailureCountStringJSONata,
    ToleratedFailurePercentage,
    ToleratedFailurePercentagePath,
    ToleratedFailurePercentageStringJSONata,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.state_task import (
    StateTask,
)
from localstack.services.stepfunctions.asl.component.state.state_fail.state_fail import StateFail
from localstack.services.stepfunctions.asl.component.state.state_pass.result import Result
from localstack.services.stepfunctions.asl.component.state.state_pass.state_pass import StatePass
from localstack.services.stepfunctions.asl.component.state.state_succeed.state_succeed import (
    StateSucceed,
)
from localstack.services.stepfunctions.asl.component.test_state.program.test_state_program import (
    TestStateProgram,
)
from localstack.services.stepfunctions.asl.component.test_state.state.common import (
    MockedCommonState,
)
from localstack.services.stepfunctions.asl.component.test_state.state.map import (
    MockedStateMap,
)
from localstack.services.stepfunctions.asl.component.test_state.state.task import (
    MockedStateTask,
)
from localstack.services.stepfunctions.asl.component.test_state.state.test_state_state_props import (
    TestStateStateProps,
)
from localstack.services.stepfunctions.asl.eval.test_state.environment import TestStateEnvironment
from localstack.services.stepfunctions.asl.parse.preprocessor import Preprocessor
from localstack.services.stepfunctions.asl.utils.encoding import to_json_str


class InspectionDataKey(enum.Enum):
    INPUT = "input"
    AFTER_INPUT_PATH = "afterInputPath"
    AFTER_PARAMETERS = "afterParameters"
    AFTER_ARGUMENTS = "afterArguments"
    RESULT = "result"
    AFTER_RESULT_SELECTOR = "afterResultSelector"
    AFTER_RESULT_PATH = "afterResultPath"
    AFTER_ITEMS_PATH = "afterItemsPath"
    REQUEST = "request"
    RESPONSE = "response"

    MAX_CONCURRENCY = "maxConcurrency"
    TOLERATED_FAILURE_COUNT = "toleratedFailureCount"
    TOLERATED_FAILURE_PERCENTAGE = "toleratedFailurePercentage"


def _decorated_updates_inspection_data(method, inspection_data_key: InspectionDataKey):
    def wrapper(env: TestStateEnvironment, *args, **kwargs):
        method(env, *args, **kwargs)
        result = env.stack[-1]
        if not isinstance(result, (int, float)):
            result = to_json_str(result)
        # We know that the enum value used here corresponds to a supported inspection data field by design.
        env.inspection_data[inspection_data_key.value] = result  # noqa

    return wrapper


def _decorate_state_field(state_field: CommonStateField, is_single_state: bool = False) -> None:
    if isinstance(state_field, StateMap):
        MockedStateMap.wrap(state_field, is_single_state)
    elif isinstance(state_field, StateTask):
        MockedStateTask.wrap(state_field, is_single_state)
    elif isinstance(state_field, (StateChoice, StatePass, StateFail, StateSucceed)):
        MockedCommonState.wrap(state_field, is_single_state)


def find_state(state_name: str, states: dict[str, CommonStateField]) -> CommonStateField | None:
    if state_name in states:
        return states[state_name]

    for state in states.values():
        if isinstance(state, StateMap):
            found_state = find_state(state_name, state.iteration_component._states.states)
            if found_state:
                return found_state


class TestStatePreprocessor(Preprocessor):
    STATE_NAME: Final[str] = "StateName"
    _state_name_stack: list[str] = []

    def to_test_state_program(
        self, tree: ParseTree, state_name: str | None = None
    ) -> TestStateProgram:
        if is_production(tree, ASLParser.RULE_state_machine):
            # full definition passed in
            program = self.visitState_machine(ctx=tree)
            state_field = find_state(state_name, program.states.states)
            _decorate_state_field(state_field, False)
            return TestStateProgram(state_field)

        if is_production(tree, ASLParser.RULE_state_decl_body):
            # single state case
            state_props = self.visitState_decl_body(ctx=tree)
            state_field = self._common_state_field_of(state_props=state_props)
            _decorate_state_field(state_field, True)
            return TestStateProgram(state_field)

        return super().visit(tree)

    def visitState_decl(self, ctx: ASLParser.State_declContext) -> CommonStateField:
        # if we are parsing a full state machine, we need to record the state_name prior to stepping
        # into the state body definition.
        state_name = self._inner_string_of(parser_rule_context=ctx.string_literal())
        self._state_name_stack.append(state_name)
        state_props: TestStateStateProps = self.visit(ctx.state_decl_body())
        state_field = self._common_state_field_of(state_props=state_props)
        return state_field

    def visitState_decl_body(self, ctx: ASLParser.State_decl_bodyContext) -> TestStateStateProps:
        self._open_query_language_scope(ctx)
        state_props = TestStateStateProps()
        state_props.name = (
            self._state_name_stack.pop(-1) if self._state_name_stack else self.STATE_NAME
        )
        for child in ctx.children:
            cmp = self.visit(child)
            state_props.add(cmp)
        if state_props.get(QueryLanguage) is None:
            state_props.add(self._get_current_query_language())
        self._close_query_language_scope()
        return state_props

    def visitInput_path_decl(self, ctx: ASLParser.Input_path_declContext) -> InputPath:
        input_path: InputPath = super().visitInput_path_decl(ctx=ctx)
        input_path._eval_body = _decorated_updates_inspection_data(
            method=input_path._eval_body,  # noqa
            inspection_data_key=InspectionDataKey.AFTER_INPUT_PATH,
        )
        return input_path

    def visitParameters_decl(self, ctx: ASLParser.Parameters_declContext) -> Parameters:
        parameters: Parameters = super().visitParameters_decl(ctx=ctx)
        parameters._eval_body = _decorated_updates_inspection_data(
            method=parameters._eval_body,  # noqa
            inspection_data_key=InspectionDataKey.AFTER_PARAMETERS,
        )
        return parameters

    def visitResult_selector_decl(
        self, ctx: ASLParser.Result_selector_declContext
    ) -> ResultSelector:
        result_selector: ResultSelector = super().visitResult_selector_decl(ctx=ctx)
        result_selector._eval_body = _decorated_updates_inspection_data(
            method=result_selector._eval_body,  # noqa
            inspection_data_key=InspectionDataKey.AFTER_RESULT_SELECTOR,
        )
        return result_selector

    def visitResult_path_decl(self, ctx: ASLParser.Result_path_declContext) -> ResultPath:
        result_path: ResultPath = super().visitResult_path_decl(ctx=ctx)
        result_path._eval_body = _decorated_updates_inspection_data(
            method=result_path._eval_body,  # noqa
            inspection_data_key=InspectionDataKey.AFTER_RESULT_PATH,
        )
        return result_path

    def visitResult_decl(self, ctx: ASLParser.Result_declContext) -> Result:
        result: Result = super().visitResult_decl(ctx=ctx)
        result._eval_body = _decorated_updates_inspection_data(
            method=result._eval_body,
            inspection_data_key=InspectionDataKey.RESULT,  # noqa
        )
        return result

    def visitMax_concurrency_int(self, ctx: ASLParser.Max_concurrency_intContext) -> MaxConcurrency:
        max_concurrency: MaxConcurrency = super().visitMax_concurrency_int(ctx)
        max_concurrency._eval_body = _decorated_updates_inspection_data(
            method=max_concurrency._eval_body,
            inspection_data_key=InspectionDataKey.MAX_CONCURRENCY,  # noqa
        )
        return max_concurrency

    def visitMax_concurrency_jsonata(
        self, ctx: ASLParser.Max_concurrency_jsonataContext
    ) -> MaxConcurrencyJSONata:
        max_concurrency_jsonata: MaxConcurrencyJSONata = super().visitMax_concurrency_jsonata(ctx)
        max_concurrency_jsonata._eval_body = _decorated_updates_inspection_data(
            method=max_concurrency_jsonata._eval_body,
            inspection_data_key=InspectionDataKey.MAX_CONCURRENCY,  # noqa
        )
        return max_concurrency_jsonata

    def visitMax_concurrency_path(
        self, ctx: ASLParser.Max_concurrency_declContext
    ) -> MaxConcurrencyPath:
        max_concurrency_path: MaxConcurrencyPath = super().visitMax_concurrency_path(ctx)
        max_concurrency_path._eval_body = _decorated_updates_inspection_data(
            method=max_concurrency_path._eval_body,
            inspection_data_key=InspectionDataKey.MAX_CONCURRENCY,  # noqa
        )
        return max_concurrency_path

    def visitTolerated_failure_count_int(self, ctx) -> ToleratedFailureCountInt:
        tolerated_failure_count: ToleratedFailureCountInt = (
            super().visitTolerated_failure_count_int(ctx)
        )
        tolerated_failure_count._eval_body = _decorated_updates_inspection_data(
            method=tolerated_failure_count._eval_body,
            inspection_data_key=InspectionDataKey.TOLERATED_FAILURE_COUNT,
        )
        return tolerated_failure_count

    def visitTolerated_failure_count_path(self, ctx) -> ToleratedFailureCountPath:
        tolerated_failure_count_path: ToleratedFailureCountPath = (
            super().visitTolerated_failure_count_path(ctx)
        )
        tolerated_failure_count_path._eval_body = _decorated_updates_inspection_data(
            method=tolerated_failure_count_path._eval_body,
            inspection_data_key=InspectionDataKey.TOLERATED_FAILURE_COUNT,
        )
        return tolerated_failure_count_path

    def visitTolerated_failure_count_string_jsonata(
        self, ctx
    ) -> ToleratedFailureCountStringJSONata:
        tolerated_failure_count_jsonata: ToleratedFailureCountStringJSONata = (
            super().visitTolerated_failure_count_string_jsonata(ctx)
        )
        tolerated_failure_count_jsonata._eval_body = _decorated_updates_inspection_data(
            method=tolerated_failure_count_jsonata._eval_body,
            inspection_data_key=InspectionDataKey.TOLERATED_FAILURE_COUNT,
        )
        return tolerated_failure_count_jsonata

    def visitTolerated_failure_percentage_number(self, ctx) -> ToleratedFailurePercentage:
        tolerated_failure_percentage: ToleratedFailurePercentage = (
            super().visitTolerated_failure_percentage_number(ctx)
        )
        tolerated_failure_percentage._eval_body = _decorated_updates_inspection_data(
            method=tolerated_failure_percentage._eval_body,
            inspection_data_key=InspectionDataKey.TOLERATED_FAILURE_PERCENTAGE,
        )
        return tolerated_failure_percentage

    def visitTolerated_failure_percentage_path(self, ctx) -> ToleratedFailurePercentagePath:
        tolerated_failure_percentage_path: ToleratedFailurePercentagePath = (
            super().visitTolerated_failure_percentage_path(ctx)
        )
        tolerated_failure_percentage_path._eval_body = _decorated_updates_inspection_data(
            method=tolerated_failure_percentage_path._eval_body,
            inspection_data_key=InspectionDataKey.TOLERATED_FAILURE_PERCENTAGE,
        )
        return tolerated_failure_percentage_path

    def visitTolerated_failure_percentage_string_jsonata(
        self, ctx
    ) -> ToleratedFailurePercentageStringJSONata:
        tolerated_failure_percentage_jsonata: ToleratedFailurePercentageStringJSONata = (
            super().visitTolerated_failure_percentage_string_jsonata(ctx)
        )
        tolerated_failure_percentage_jsonata._eval_body = _decorated_updates_inspection_data(
            method=tolerated_failure_percentage_jsonata._eval_body,
            inspection_data_key=InspectionDataKey.TOLERATED_FAILURE_PERCENTAGE,
        )
        return tolerated_failure_percentage_jsonata

    def visitItems_path_decl(self, ctx) -> ItemsPath:
        items_path: ItemsPath = super().visitItems_path_decl(ctx)
        items_path._eval_body = _decorated_updates_inspection_data(
            method=items_path._eval_body,
            inspection_data_key=InspectionDataKey.AFTER_ITEMS_PATH,
        )
        return items_path

    def visitArguments_string_jsonata(self, ctx):
        arguments: ArgumentsStringJSONata = super().visitArguments_string_jsonata(ctx)
        arguments._eval_body = _decorated_updates_inspection_data(
            method=arguments._eval_body,
            inspection_data_key=InspectionDataKey.AFTER_ARGUMENTS,
        )
        return arguments

    def visitArguments_jsonata_template_value_object(self, ctx):
        arguments: ArgumentsJSONataTemplateValueObject = (
            super().visitArguments_jsonata_template_value_object(ctx)
        )
        arguments._eval_body = _decorated_updates_inspection_data(
            method=arguments._eval_body,
            inspection_data_key=InspectionDataKey.AFTER_ARGUMENTS,
        )
        return arguments
