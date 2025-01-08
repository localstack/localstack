from typing import Any, Final, Optional

from botocore.exceptions import ClientError

from localstack.aws.api.stepfunctions import HistoryEventType, TaskFailedEventDetails
from localstack.services.stepfunctions.asl.component.common.error_name.custom_error_name import (
    CustomErrorName,
)
from localstack.services.stepfunctions.asl.component.common.error_name.failure_event import (
    FailureEvent,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.credentials import (
    StateCredentials,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.service.resource import (
    ResourceCondition,
    ResourceRuntimePart,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.service.state_task_service_callback import (
    StateTaskServiceCallback,
)
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.services.stepfunctions.asl.eval.event.event_detail import EventDetails
from localstack.services.stepfunctions.asl.utils.boto_client import boto_client_for
from localstack.services.stepfunctions.asl.utils.encoding import to_json_str

_SUPPORTED_INTEGRATION_PATTERNS: Final[set[ResourceCondition]] = {
    ResourceCondition.WaitForTaskToken,
}
_ERROR_NAME_CLIENT: Final[str] = "SQS.SdkClientException"
_ERROR_NAME_AWS: Final[str] = "SQS.AmazonSQSException"
_SUPPORTED_API_PARAM_BINDINGS: Final[dict[str, set[str]]] = {
    "sendmessage": {
        "DelaySeconds",
        "MessageAttributes",
        "MessageBody",
        "MessageDeduplicationId",
        "MessageGroupId",
        "QueueUrl",
    }
}


class StateTaskServiceSqs(StateTaskServiceCallback):
    def __init__(self):
        super().__init__(supported_integration_patterns=_SUPPORTED_INTEGRATION_PATTERNS)

    def _get_supported_parameters(self) -> Optional[set[str]]:
        return _SUPPORTED_API_PARAM_BINDINGS.get(self.resource.api_action.lower())

    def _from_error(self, env: Environment, ex: Exception) -> FailureEvent:
        if isinstance(ex, ClientError):
            return FailureEvent(
                env=env,
                error_name=CustomErrorName(_ERROR_NAME_CLIENT),
                event_type=HistoryEventType.TaskFailed,
                event_details=EventDetails(
                    taskFailedEventDetails=TaskFailedEventDetails(
                        error=_ERROR_NAME_CLIENT,
                        cause=ex.response["Error"][
                            "Message"
                        ],  # TODO: update to report expected cause.
                        resource=self._get_sfn_resource(),
                        resourceType=self._get_sfn_resource_type(),
                    )
                ),
            )
        return super()._from_error(env=env, ex=ex)

    def _normalise_response(
        self,
        response: Any,
        boto_service_name: Optional[str] = None,
        service_action_name: Optional[str] = None,
    ) -> None:
        super()._normalise_response(
            response=response,
            boto_service_name=boto_service_name,
            service_action_name=service_action_name,
        )
        # Normalise output value keys to SFN standard for Md5OfMessageBody and Md5OfMessageAttributes
        if response and "Md5OfMessageBody" in response:
            md5_message_body = response.pop("Md5OfMessageBody")
            response["MD5OfMessageBody"] = md5_message_body

        if response and "Md5OfMessageAttributes" in response:
            md5_message_attributes = response.pop("Md5OfMessageAttributes")
            response["MD5OfMessageAttributes"] = md5_message_attributes

    def _eval_service_task(
        self,
        env: Environment,
        resource_runtime_part: ResourceRuntimePart,
        normalised_parameters: dict,
        state_credentials: StateCredentials,
    ):
        # TODO: Stepfunctions automatically dumps to json MessageBody's definitions.
        #  Are these other similar scenarios?
        if "MessageBody" in normalised_parameters:
            message_body = normalised_parameters["MessageBody"]
            if message_body is not None and not isinstance(message_body, str):
                normalised_parameters["MessageBody"] = to_json_str(message_body)

        service_name = self._get_boto_service_name()
        api_action = self._get_boto_service_action()
        sqs_client = boto_client_for(
            service=service_name,
            region=resource_runtime_part.region,
            state_credentials=state_credentials,
        )
        response = getattr(sqs_client, api_action)(**normalised_parameters)
        response.pop("ResponseMetadata", None)
        env.stack.append(response)
