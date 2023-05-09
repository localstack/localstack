from typing import Final, Optional

from botocore.exceptions import ClientError

from localstack.aws.api.stepfunctions import (
    HistoryEventExecutionDataDetails,
    HistoryEventType,
    TaskFailedEventDetails,
    TaskScheduledEventDetails,
    TaskStartedEventDetails,
    TaskSucceededEventDetails,
)
from localstack.services.stepfunctions.asl.component.common.error_name.custom_error_name import (
    CustomErrorName,
)
from localstack.services.stepfunctions.asl.component.common.error_name.failure_event import (
    FailureEvent,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.service.state_task_service import (
    StateTaskService,
)
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.services.stepfunctions.asl.eval.event.event_detail import EventDetails
from localstack.services.stepfunctions.asl.utils.encoding import to_json_str
from localstack.utils.aws import aws_stack
from localstack.utils.strings import camel_to_snake_case


class StateTaskServiceSqs(StateTaskService):
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
                        resource=self.resource.api_action,
                        resourceType=self.resource.service_name,
                    )
                ),
            )
        else:
            return FailureEvent(
                error_name=CustomErrorName(self._ERROR_NAME_AWS),
                event_type=HistoryEventType.TaskFailed,
                event_details=EventDetails(
                    taskFailedEventDetails=TaskFailedEventDetails(
                        error=self._ERROR_NAME_AWS,
                        cause=str(ex),  # TODO: update to report expected cause.
                        resource=self.resource.api_action,
                        resourceType=self.resource.service_name,
                    )
                ),
            )

    def _eval_parameters(self, env: Environment) -> dict:
        api_action: str = self.resource.api_action
        supported_parameters: Optional[set[str]] = self._SUPPORTED_API_PARAM_BINDINGS.get(
            api_action.lower(), None
        )
        if supported_parameters is None:
            raise RuntimeError("TODO: raise unsupported api error?")

        parameters: dict = super()._eval_parameters(env=env)
        unsupported_parameters: list[str] = [
            parameter for parameter in parameters.keys() if parameter not in supported_parameters
        ]
        if unsupported_parameters:
            for unsupported_parameter in unsupported_parameters:
                parameters.pop(unsupported_parameter, None)

        return parameters

    def _eval_execution(self, env: Environment) -> None:
        parameters = self._eval_parameters(env=env)

        parameters_str = to_json_str(parameters)
        env.event_history.add_event(
            hist_type_event=HistoryEventType.TaskScheduled,
            event_detail=EventDetails(
                taskScheduledEventDetails=TaskScheduledEventDetails(
                    resourceType=self._get_resource_type(),
                    resource=self.resource.api_action,
                    region=self.resource.region,
                    parameters=parameters_str,
                )
            ),
        )
        env.event_history.add_event(
            hist_type_event=HistoryEventType.TaskStarted,
            event_detail=EventDetails(
                taskStartedEventDetails=TaskStartedEventDetails(
                    resourceType=self._get_resource_type(),
                    resource=self.resource.api_action,
                )
            ),
        )

        api_action = camel_to_snake_case(self.resource.api_action)
        sqs_client = aws_stack.create_external_boto_client("sqs")
        response = getattr(sqs_client, api_action)(**parameters)
        response.pop("ResponseMetadata", None)
        env.stack.append(response)

        env.event_history.add_event(
            hist_type_event=HistoryEventType.TaskSucceeded,
            event_detail=EventDetails(
                taskSucceededEventDetails=TaskSucceededEventDetails(
                    resourceType=self._get_resource_type(),
                    resource=self.resource.api_action,
                    output=to_json_str(response),
                    outputDetails=HistoryEventExecutionDataDetails(truncated=False),
                )
            ),
        )
