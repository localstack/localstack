from localstack.services.stepfunctions.asl.antlr.runtime.ASLParser import ASLParser
from localstack.services.stepfunctions.asl.component.state.state_props import StateProps
from localstack.services.stepfunctions.asl.component.test_case.test_case_program import (
    TestCaseProgram,
)
from localstack.services.stepfunctions.asl.parse.preprocessor import Preprocessor


class TestCasePreprocessor(Preprocessor):
    def visitState_decl_body(self, ctx: ASLParser.State_decl_bodyContext) -> TestCaseProgram:
        state_props = StateProps()
        for child in ctx.children:
            cmp = self.visit(child)
            state_props.add(cmp)
        state_field = self._common_state_field_of(state_props=state_props)
        return TestCaseProgram(state_field)
