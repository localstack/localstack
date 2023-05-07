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
from localstack.services.stepfunctions.asl.component.common.error_name.states_error_name import (
    StatesErrorName,
)
from localstack.services.stepfunctions.asl.component.common.error_name.states_error_name_type import (
    StatesErrorNameType,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.service.state_task_service import (
    StateTaskService,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.state_task_lambda import (
    LambdaFunctionErrorException,
    StateTaskLambda,
)
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.services.stepfunctions.asl.eval.event.event_detail import EventDetails
from localstack.services.stepfunctions.asl.utils.encoding import to_json_str


class StateTaskServiceLambda(StateTaskService, StateTaskLambda):
    @staticmethod
    def _error_cause_from_client_error(client_error: ClientError) -> tuple[str, str]:
        error_code: str = client_error.response["Error"]["Code"]
        error_msg: str = client_error.response["Error"]["Message"]
        response_details = "; ".join(
            [
                "Service: AWSLambda",
                f"Status Code: {client_error.response['ResponseMetadata']['HTTPStatusCode']}",
                f"Error Code: {error_code}",
                f"Request ID: {client_error.response['ResponseMetadata']['RequestId']}",
                "Proxy: null",
            ]
        )
        error = f"Lambda.{error_code}"
        cause = f"{error_msg} ({response_details})"
        return error, cause

    def _from_error(self, env: Environment, ex: Exception) -> FailureEvent:
        if isinstance(ex, LambdaFunctionErrorException):
            error = "Exception"
            error_name = CustomErrorName(error)
            cause = ex.payload
        elif isinstance(ex, ClientError):
            error, cause = self._error_cause_from_client_error(ex)
            error_name = CustomErrorName(error)
        else:
            error = "Exception"
            error_name = StatesErrorName(typ=StatesErrorNameType.StatesTaskFailed)
            cause = str(ex)

        return FailureEvent(
            error_name=error_name,
            event_type=HistoryEventType.TaskFailed,
            event_details=EventDetails(
                taskFailedEventDetails=TaskFailedEventDetails(
                    error=error,
                    cause=cause,
                    resourceType=self._get_resource_type(),
                    resource=self.resource.api_action,
                )
            ),
        )

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

        super()._exec_lambda_function(env=env)
        response = env.stack[-1]

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
