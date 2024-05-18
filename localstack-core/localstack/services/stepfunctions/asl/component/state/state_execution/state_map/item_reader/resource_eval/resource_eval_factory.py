from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.item_reader.resource_eval.resource_eval import (
    ResourceEval,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.item_reader.resource_eval.resource_eval_s3 import (
    ResourceEvalS3,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.service.resource import (
    Resource,
    ServiceResource,
)


def resource_eval_for(resource: Resource) -> ResourceEval:
    if isinstance(resource, ServiceResource):
        match resource.service_name:
            case "s3":
                return ResourceEvalS3(resource=resource)
    raise ValueError(
        f"ItemReader's Resource fields must be states service resource, instead got '{resource.resource_arn}'."
    )
