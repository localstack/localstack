from typing import Final

from localstack.services.stepfunctions.asl.antlr.runtime.ASLParser import ASLParser
from localstack.services.stepfunctions.asl.component.common.parameters import Parameters
from localstack.services.stepfunctions.asl.component.common.path.input_path import InputPath
from localstack.services.stepfunctions.asl.component.common.path.result_path import ResultPath
from localstack.services.stepfunctions.asl.component.common.payload.payloadvalue.payloadtmpl.payload_tmpl import (
    PayloadTmpl,
)
from localstack.services.stepfunctions.asl.component.common.result_selector import ResultSelector
from localstack.services.stepfunctions.asl.component.state.state_pass.result import Result
from localstack.services.stepfunctions.asl.component.test_state.common.parameters import (
    TestStateParameters,
)
from localstack.services.stepfunctions.asl.component.test_state.common.path.input_path import (
    TestStateInputPath,
)
from localstack.services.stepfunctions.asl.component.test_state.common.path.result_path import (
    TestStateResultPath,
)
from localstack.services.stepfunctions.asl.component.test_state.common.result_selector import (
    TestStateResultSelector,
)
from localstack.services.stepfunctions.asl.component.test_state.program.test_state_program import (
    TestStateProgram,
)
from localstack.services.stepfunctions.asl.component.test_state.state.state_pass.result import (
    TestStateResult,
)
from localstack.services.stepfunctions.asl.component.test_state.state.test_state_state_props import (
    TestStateStateProps,
)
from localstack.services.stepfunctions.asl.parse.preprocessor import Preprocessor


class TestStatePreprocessor(Preprocessor):
    STATE_NAME: Final[str] = "TestState"

    def visitState_decl_body(self, ctx: ASLParser.State_decl_bodyContext) -> TestStateProgram:
        state_props = TestStateStateProps()
        state_props.name = self.STATE_NAME
        for child in ctx.children:
            cmp = self.visit(child)
            state_props.add(cmp)

        # Enforce the following missing fields to ensure inspection level traceability.
        if not state_props.get(InputPath):
            state_props.add(TestStateInputPath(TestStateInputPath.DEFAULT_PATH))
        # if not state_props.get(Parameters):
        #     state_props.add(TestStateParameters(payload_tmpl=None))
        # if not state_props.get(ResultSelector):
        #     state_props.add(TestStateResultSelector(payload_tmpl=None))
        # if not state_props.get(ResultPath):
        #     state_props.add(TestStateResultPath(TestStateResultPath.DEFAULT_PATH))

        state_field = self._common_state_field_of(state_props=state_props)
        return TestStateProgram(state_field)

    def visitInput_path_decl(self, ctx: ASLParser.Input_path_declContext) -> InputPath:
        inner_str = self._inner_string_of(parse_tree=ctx.children[-1])
        return TestStateInputPath(input_path_src=inner_str)

    def visitParameters_decl(self, ctx: ASLParser.Parameters_declContext) -> Parameters:
        payload_tmpl: PayloadTmpl = self.visit(ctx.payload_tmpl_decl())
        return TestStateParameters(payload_tmpl=payload_tmpl)

    def visitResult_selector_decl(
        self, ctx: ASLParser.Result_selector_declContext
    ) -> ResultSelector:
        payload_tmpl: PayloadTmpl = self.visit(ctx.payload_tmpl_decl())
        return TestStateResultSelector(payload_tmpl=payload_tmpl)

    def visitResult_path_decl(self, ctx: ASLParser.Result_path_declContext) -> ResultPath:
        inner_str = self._inner_string_of(parse_tree=ctx.children[-1])
        return TestStateResultPath(result_path_src=inner_str)

    def visitResult_decl(self, ctx: ASLParser.Result_declContext) -> TestStateResult:
        result: Result = super().visitResult_decl(ctx=ctx)
        return TestStateResult(result_obj=result.result_obj)
