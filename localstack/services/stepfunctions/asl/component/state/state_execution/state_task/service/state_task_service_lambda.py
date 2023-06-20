from botocore.exceptions import ClientError

from localstack.aws.api.stepfunctions import HistoryEventType, TaskFailedEventDetails
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
from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.service.state_task_service_callback import (
    StateTaskServiceCallback,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.state_task_lambda import (
    LambdaFunctionErrorException,
    StateTaskLambda,
)
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.services.stepfunctions.asl.eval.event.event_detail import EventDetails


class StateTaskServiceLambda(StateTaskServiceCallback, StateTaskLambda):
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
                    resource=self._get_sfn_resource(),
                    resourceType=self._get_sfn_resource_type(),
                )
            ),
        )

    def _eval_service_task(self, env: Environment, parameters: dict) -> None:
        super()._exec_lambda_function(env=env)
