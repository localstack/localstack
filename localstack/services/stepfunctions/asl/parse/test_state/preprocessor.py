import enum
from typing import Final

from localstack.services.stepfunctions.asl.antlr.runtime.ASLParser import ASLParser
from localstack.services.stepfunctions.asl.component.common.parameters import Parameters
from localstack.services.stepfunctions.asl.component.common.path.input_path import InputPath
from localstack.services.stepfunctions.asl.component.common.path.result_path import ResultPath
from localstack.services.stepfunctions.asl.component.common.result_selector import ResultSelector
from localstack.services.stepfunctions.asl.component.state.state import CommonStateField
from localstack.services.stepfunctions.asl.component.state.state_choice.state_choice import (
    StateChoice,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.execute_state import (
    ExecutionState,
)
from localstack.services.stepfunctions.asl.component.state.state_pass.result import Result
from localstack.services.stepfunctions.asl.component.test_state.program.test_state_program import (
    TestStateProgram,
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
    RESULT = "result"
    AFTER_RESULT_SELECTOR = "afterResultSelector"
    AFTER_RESULT_PATH = "afterResultPath"
    REQUEST = "request"
    RESPONSE = "response"


def _decorated_updated_choice_inspection_data(method):
    def wrapper(env: TestStateEnvironment, *args, **kwargs):
        method(env, *args, **kwargs)
        env.set_choice_selected(env.next_state_name)

    return wrapper


def _decorated_updates_inspection_data(method, inspection_data_key: InspectionDataKey):
    def wrapper(env: TestStateEnvironment, *args, **kwargs):
        method(env, *args, **kwargs)
        result = to_json_str(env.stack[-1])
        env.inspection_data[inspection_data_key.value] = result  # noqa: we know that the here value is a supported inspection data field by design.

    return wrapper


def _decorate_state_field(state_field: CommonStateField) -> None:
    if isinstance(state_field, ExecutionState):
        state_field._eval_execution = _decorated_updates_inspection_data(
            method=state_field._eval_execution,  # noqa: as part of the decoration we access this protected member.
            inspection_data_key=InspectionDataKey.RESULT,
        )
    elif isinstance(state_field, StateChoice):
        state_field._eval_body = _decorated_updated_choice_inspection_data(
            method=state_field._eval_body  # noqa: as part of the decoration we access this protected member.
        )


class TestStatePreprocessor(Preprocessor):
    STATE_NAME: Final[str] = "TestState"

    def visitState_decl_body(self, ctx: ASLParser.State_decl_bodyContext) -> TestStateProgram:
        state_props = TestStateStateProps()
        state_props.name = self.STATE_NAME
        for child in ctx.children:
            cmp = self.visit(child)
            state_props.add(cmp)
        state_field = self._common_state_field_of(state_props=state_props)
        _decorate_state_field(state_field)
        return TestStateProgram(state_field)

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
