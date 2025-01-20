import json
import logging
from typing import Final, Optional

from botocore.exceptions import ClientError

from localstack.aws.api.stepfunctions import HistoryEventType, TaskFailedEventDetails
from localstack.services.stepfunctions.asl.component.common.error_name.custom_error_name import (
    CustomErrorName,
)
from localstack.services.stepfunctions.asl.component.common.error_name.failure_event import (
    FailureEvent,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_task import (
    lambda_eval_utils,
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

LOG = logging.getLogger(__name__)


_SUPPORTED_INTEGRATION_PATTERNS: Final[set[ResourceCondition]] = {
    ResourceCondition.WaitForTaskToken,
}
_SUPPORTED_API_PARAM_BINDINGS: Final[dict[str, set[str]]] = {
    "invoke": {
        "ClientContext",
        "FunctionName",
        "InvocationType",
        "Qualifier",
        "Payload",
        # Outside the specification, but supported in practice:
        "LogType",
    }
}


class StateTaskServiceLambda(StateTaskServiceCallback):
    def __init__(self):
        super().__init__(supported_integration_patterns=_SUPPORTED_INTEGRATION_PATTERNS)

    def _get_supported_parameters(self) -> Optional[set[str]]:
        return _SUPPORTED_API_PARAM_BINDINGS.get(self.resource.api_action.lower())

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
        if isinstance(ex, lambda_eval_utils.LambdaFunctionErrorException):
            cause = ex.payload
            try:
                cause_object = json.loads(cause)
                error = cause_object["errorType"]
            except Exception as ex:
                LOG.warning(
                    "Could not retrieve 'errorType' field from LambdaFunctionErrorException object: %s",
                    ex,
                )
                error = "Exception"
            error_name = CustomErrorName(error)
        elif isinstance(ex, ClientError):
            error, cause = self._error_cause_from_client_error(ex)
            error_name = CustomErrorName(error)
        else:
            return super()._from_error(env=env, ex=ex)
        return FailureEvent(
            env=env,
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

    def _normalise_parameters(
        self,
        parameters: dict,
        boto_service_name: Optional[str] = None,
        service_action_name: Optional[str] = None,
    ) -> None:
        # Run Payload value casting before normalisation.
        if "Payload" in parameters:
            parameters["Payload"] = lambda_eval_utils.to_payload_type(parameters["Payload"])
        super()._normalise_parameters(
            parameters=parameters,
            boto_service_name=boto_service_name,
            service_action_name=service_action_name,
        )

    def _eval_service_task(
        self,
        env: Environment,
        resource_runtime_part: ResourceRuntimePart,
        normalised_parameters: dict,
        state_credentials: StateCredentials,
    ):
        lambda_eval_utils.exec_lambda_function(
            env=env,
            parameters=normalised_parameters,
            region=resource_runtime_part.region,
            state_credentials=state_credentials,
        )
