import json

from botocore.exceptions import ClientError

from localstack.aws.api.stepfunctions import (
    HistoryEventType,
    TaskFailedEventDetails,
    TaskScheduledEventDetails,
    TaskStartedEventDetails,
)
from localstack.aws.protocol.service_router import get_service_catalog
from localstack.services.stepfunctions.asl.component.common.error_name.error_name import ErrorName
from localstack.services.stepfunctions.asl.component.common.error_name.failure_event import (
    FailureEvent,
)
from localstack.services.stepfunctions.asl.component.common.error_name.states_error_name_type import (
    StatesErrorNameType,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.state_task_service import (
    StateTaskService,
)
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.services.stepfunctions.asl.eval.event.event_detail import EventDetails
from localstack.utils.aws import aws_stack
from localstack.utils.common import camel_to_snake_case


class StateTaskServiceAwsSdk(StateTaskService):
    def _get_resource_type(self) -> str:
        return f"{self.resource.service_name}:{self.resource.api_name}"

    def _eval_execution(self, env: Environment) -> None:
        super()._eval_execution(env=env)

        api_name = self.resource.api_name
        api_action = camel_to_snake_case(self.resource.api_action)

        args = {}
        if self.parameters:
            self.parameters.eval(env=env)
            parameters = env.stack.pop()
            args.update(parameters)

        # Simulate scheduled-start workflow.
        parameters_str = json.dumps(args)
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

        api_client = aws_stack.create_external_boto_client(service_name=api_name)

        response = getattr(api_client, api_action)(**args)
        response.pop("ResponseMetadata", None)

        env.stack.append(response)

    @staticmethod
    def _normalise_service_name(service_name: str) -> str:
        return get_service_catalog().get(service_name).service_id.replace(" ", "")

    @staticmethod
    def _normalise_exception_name(norm_service_name: str, ex: ClientError) -> str:
        ex_name = ex.__class__.__name__
        return f"{norm_service_name}.{norm_service_name if ex_name == 'ClientError' else ex_name}Exception"

    def _from_error(self, env: Environment, ex: Exception) -> FailureEvent:
        if isinstance(ex, ClientError):
            error_message: str = ex.response["Error"]["Message"]

            norm_service_name: str = self._normalise_service_name(self.resource.api_name)

            cause_details = [
                f"Service: {norm_service_name}",
                f"Status Code: {ex.response['ResponseMetadata']['HTTPStatusCode']}",
                f"Request ID: {ex.response['ResponseMetadata']['RequestId']}",
            ]
            if "HostId" in ex.response["ResponseMetadata"]:
                cause_details.append(
                    f'Extended Request ID: {ex.response["ResponseMetadata"]["HostId"]}'
                )

            error: str = self._normalise_exception_name(norm_service_name, ex)
            cause: str = f"{error_message} ({', '.join(cause_details)})"

            return FailureEvent(
                error_name=ErrorName(StatesErrorNameType.StatesTaskFailed.to_name()),
                event_type=HistoryEventType.TaskFailed,
                event_details=EventDetails(
                    taskFailedEventDetails=TaskFailedEventDetails(
                        resourceType=self._get_resource_type(),
                        resource=self.resource.api_action,
                        error=error,
                        cause=cause,
                    )
                ),
            )
        return super()._from_error(env=env, ex=ex)
