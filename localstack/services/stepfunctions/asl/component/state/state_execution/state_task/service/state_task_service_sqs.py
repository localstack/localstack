from typing import Final, Optional

from botocore.config import Config
from botocore.exceptions import ClientError

from localstack.aws.api.stepfunctions import HistoryEventType, TaskFailedEventDetails
from localstack.services.stepfunctions.asl.component.common.error_name.custom_error_name import (
    CustomErrorName,
)
from localstack.services.stepfunctions.asl.component.common.error_name.failure_event import (
    FailureEvent,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.service.state_task_service_callback import (
    StateTaskServiceCallback,
)
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.services.stepfunctions.asl.eval.event.event_detail import EventDetails
from localstack.services.stepfunctions.asl.utils.encoding import to_json_str
from localstack.utils.aws import aws_stack
from localstack.utils.strings import camel_to_snake_case


class StateTaskServiceSqs(StateTaskServiceCallback):
    _ERROR_NAME_CLIENT: Final[str] = "SQS.SdkClientException"
    _ERROR_NAME_AWS: Final[str] = "SQS.AmazonSQSException"

    _SUPPORTED_API_PARAM_BINDINGS: Final[dict[str, set[str]]] = {
        "sendmessage": {
            "DelaySeconds",
            "MessageAttribute",
            "MessageBody",
            "MessageDeduplicationId",
            "MessageGroupId",
            "QueueUrl",
        }
    }

    def _get_supported_parameters(self) -> Optional[set[str]]:
        return self._SUPPORTED_API_PARAM_BINDINGS.get(self.resource.api_action.lower())

    def _from_error(self, env: Environment, ex: Exception) -> FailureEvent:
        if isinstance(ex, ClientError):
            return FailureEvent(
                error_name=CustomErrorName(self._ERROR_NAME_CLIENT),
                event_type=HistoryEventType.TaskFailed,
                event_details=EventDetails(
                    taskFailedEventDetails=TaskFailedEventDetails(
                        error=self._ERROR_NAME_CLIENT,
                        cause=ex.response["Error"][
                            "Message"
                        ],  # TODO: update to report expected cause.
                        resource=self._get_sfn_resource(),
                        resourceType=self._get_sfn_resource_type(),
                    )
                ),
            )
        return super()._from_error(env=env, ex=ex)

    def _eval_service_task(self, env: Environment, parameters: dict) -> None:
        # TODO: Stepfunctions automatically dumps to json MessageBody's definitions.
        #  Are these other similar scenarios?
        if "MessageBody" in parameters:
            message_body = parameters["MessageBody"]
            if message_body is not None and not isinstance(message_body, str):
                parameters["MessageBody"] = to_json_str(message_body)

        api_action = camel_to_snake_case(self.resource.api_action)
        sqs_client = aws_stack.connect_to_service("sqs", config=Config(parameter_validation=False))
        response = getattr(sqs_client, api_action)(**parameters)
        response.pop("ResponseMetadata", None)
        env.stack.append(response)
