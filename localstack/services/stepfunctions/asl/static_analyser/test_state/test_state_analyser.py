from typing import Final

from localstack.services.stepfunctions.asl.antlr.runtime.ASLParser import ASLParser
from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.service.resource import (
    ActivityResource,
    Resource,
    ServiceResource,
)
from localstack.services.stepfunctions.asl.component.state.state_type import StateType
from localstack.services.stepfunctions.asl.static_analyser.static_analyser import StaticAnalyser


class TestStateStaticAnalyser(StaticAnalyser):
    _SUPPORTED_STATE_TYPES: Final[set[StateType]] = {
        StateType.Choice,
        StateType.Pass,
        StateType.Succeed,
        StateType.Fail,
        StateType.Wait,
    }

    def analyse(self, program_tree) -> None:
        self.visitState_decl_body(program_tree)

    def visitState_type(self, ctx: ASLParser.State_typeContext) -> None:
        state_type_value: int = ctx.children[0].symbol.type
        state_type = StateType(state_type_value)
        if state_type not in self._SUPPORTED_STATE_TYPES:
            raise ValueError(f"TODO ${state_type}")

    def visitResource_decl(self, ctx: ASLParser.Resource_declContext) -> None:
        resource_str: str = ctx.keyword_or_string().getText()[1:-1]
        resource = Resource.from_resource_arn(resource_str)

        if isinstance(resource, ActivityResource):
            raise ValueError("TODO: ActivityResource")

        if isinstance(resource, ServiceResource):
            if resource.condition is not None:
                raise ValueError(f"TODO: condition {resource.condition}")
