from localstack.services.stepfunctions.asl.antlr.runtime.ASLParser import ASLParser
from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.service.resource import (
    ActivityResource,
    Resource,
    ResourceCondition,
    ServiceResource,
)
from localstack.services.stepfunctions.asl.static_analyser.static_analyser import StaticAnalyser


class ExpressStaticAnalyser(StaticAnalyser):
    def visitResource_decl(self, ctx: ASLParser.Resource_declContext) -> None:
        # TODO add resource path to the error messages.

        resource_str: str = ctx.keyword_or_string().getText()[1:-1]
        resource = Resource.from_resource_arn(resource_str)

        if isinstance(resource, ActivityResource):
            raise ValueError(
                "Invalid State Machine Definition: 'SCHEMA_VALIDATION_FAILED: "
                "Express state machine does not support Activity ARN'"
            )

        if isinstance(resource, ServiceResource):
            if resource.condition == ResourceCondition.WaitForTaskToken:
                raise ValueError(
                    "Invalid State Machine Definition: 'SCHEMA_VALIDATION_FAILED: "
                    "Express state machine does not support '.sync' service integration."
                )
            if resource.condition is not None:
                raise ValueError(
                    "Invalid State Machine Definition: 'SCHEMA_VALIDATION_FAILED: "
                    f"Express state machine does not support .'{resource.condition}' service integration."
                )
