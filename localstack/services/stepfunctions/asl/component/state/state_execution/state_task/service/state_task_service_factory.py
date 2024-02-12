from __future__ import annotations

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
        case unknown:
            raise NotImplementedError(f"Unsupported service: '{unknown}'.")  # noqa
