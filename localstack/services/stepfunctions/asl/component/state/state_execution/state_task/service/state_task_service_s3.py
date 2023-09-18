from typing import Final, Optional

from botocore.config import Config
from botocore.exceptions import ClientError

from localstack.aws.api.stepfunctions import HistoryEventType, TaskFailedEventDetails
from localstack.aws.connect import connect_externally_to
from localstack.services.stepfunctions.asl.component.common.error_name.custom_error_name import (
    CustomErrorName,
)
from localstack.services.stepfunctions.asl.component.common.error_name.failure_event import (
    FailureEvent,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.service.state_task_service import \
    StateTaskService
from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.service.state_task_service_callback import (
    StateTaskServiceCallback,
)
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.services.stepfunctions.asl.eval.event.event_detail import EventDetails
from localstack.services.stepfunctions.asl.utils.encoding import to_json_str
from localstack.utils.strings import camel_to_snake_case


class StateTaskServiceS3(StateTaskService):

    # TODO: investigate error behaviour.
    def _from_error(self, env: Environment, ex: Exception) -> FailureEvent:
        return super()._from_error(env=env, ex=ex)

    def _eval_service_task(self, env: Environment, parameters: dict) -> None:
        api_action = camel_to_snake_case(self.resource.api_action)
        sqs_client = connect_externally_to(config=Config(parameter_validation=False)).s3
        response = getattr(sqs_client, api_action)(**parameters)
        response.pop("ResponseMetadata", None)
        env.stack.append(response)
