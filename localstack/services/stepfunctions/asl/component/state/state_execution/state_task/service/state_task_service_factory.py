from __future__ import annotations

import abc

from localstack.aws.api.stepfunctions import (
    HistoryEventExecutionDataDetails,
    HistoryEventType,
    TaskScheduledEventDetails,
    TaskStartedEventDetails,
    TaskSucceededEventDetails,
    TaskTimedOutEventDetails,
)
from localstack.services.stepfunctions.asl.component.common.error_name.failure_event import (
    FailureEvent,
)
from localstack.services.stepfunctions.asl.component.common.error_name.states_error_name import (
    StatesErrorName,
)
from localstack.services.stepfunctions.asl.component.common.error_name.states_error_name_type import (
    StatesErrorNameType,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.service.resource import (
    ServiceResource,
)
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
from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.state_task import (
    StateTask,
)
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.services.stepfunctions.asl.eval.event.event_detail import EventDetails
from localstack.services.stepfunctions.asl.utils.encoding import to_json_str


# TODO: improve on factory constructor (don't use SubtypeManager)
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
        case unknown:
            raise NotImplementedError(f"Unsupported service: '{unknown}'.")  # noqa
