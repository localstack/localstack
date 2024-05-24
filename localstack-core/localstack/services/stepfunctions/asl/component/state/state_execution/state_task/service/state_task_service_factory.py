from __future__ import annotations

from typing import Final

from antlr4 import RecognitionException

from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.service.state_task_service import (
    StateTaskService,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.service.state_task_service_api_gateway import (
    StateTaskServiceApiGateway,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.service.state_task_service_aws_sdk import (
    StateTaskServiceAwsSdk,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.service.state_task_service_dynamodb import (
    StateTaskServiceDynamoDB,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.service.state_task_service_ecs import (
    StateTaskServiceEcs,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.service.state_task_service_events import (
    StateTaskServiceEvents,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.service.state_task_service_glue import (
    StateTaskServiceGlue,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.service.state_task_service_lambda import (
    StateTaskServiceLambda,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.service.state_task_service_sfn import (
    StateTaskServiceSfn,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.service.state_task_service_sns import (
    StateTaskServiceSns,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.service.state_task_service_sqs import (
    StateTaskServiceSqs,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.service.state_task_service_unsupported import (
    StateTaskServiceUnsupported,
)

_UNSUPPORTED_SERVICE_NAMES: Final[set[str]] = {
    "athena",
    "batch",
    "bedrock",
    "codebuild",
    "eks",
    "elasticmapreduce",
    "emr-containers",
    "emr-serverless",
    "databrew",
    "mediaconvert",
    "sagemaker",
}


# TODO: improve on factory constructor (don't use SubtypeManager: cannot reuse state task instances).
def state_task_service_for(service_name: str) -> StateTaskService:
    match service_name:
        case "aws-sdk":
            return StateTaskServiceAwsSdk()
        case "lambda":
            return StateTaskServiceLambda()
        case "sqs":
            return StateTaskServiceSqs()
        case "states":
            return StateTaskServiceSfn()
        case "dynamodb":
            return StateTaskServiceDynamoDB()
        case "apigateway":
            return StateTaskServiceApiGateway()
        case "sns":
            return StateTaskServiceSns()
        case "events":
            return StateTaskServiceEvents()
        case "ecs":
            return StateTaskServiceEcs()
        case "glue":
            return StateTaskServiceGlue()
        case _ if service_name in _UNSUPPORTED_SERVICE_NAMES:
            return StateTaskServiceUnsupported()
        case unknown:
            raise RecognitionException(f"Unknown service '{unknown}'")
