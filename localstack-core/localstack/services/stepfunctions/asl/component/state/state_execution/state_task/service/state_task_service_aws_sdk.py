import logging
from typing import Final

from botocore.exceptions import ClientError, UnknownServiceError

from localstack.aws.api.stepfunctions import HistoryEventType, TaskFailedEventDetails
from localstack.aws.spec import get_service_catalog
from localstack.services.stepfunctions.asl.component.common.error_name.error_name import ErrorName
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

LOG = logging.getLogger(__name__)

_SUPPORTED_INTEGRATION_PATTERNS: Final[set[ResourceCondition]] = {
    ResourceCondition.WaitForTaskToken,
}

# Defines bindings of lower-cased service names to the StepFunctions service name included in error messages.
_SERVICE_ERROR_NAMES = {"dynamodb": "DynamoDb", "sfn": "Sfn"}


class StateTaskServiceAwsSdk(StateTaskServiceCallback):
    def __init__(self):
        super().__init__(supported_integration_patterns=_SUPPORTED_INTEGRATION_PATTERNS)

    def _validate_service_integration_is_supported(self):
        # As no aws-sdk support catalog is available, allow invalid aws-sdk integration to fail at runtime.
        pass

    def _get_sfn_resource_type(self) -> str:
        return f"{self.resource.service_name}:{self.resource.api_name}"

    @staticmethod
    def _normalise_service_error_name(service_name: str) -> str:
        # Computes the normalised service error name for the given service.

        # Return the explicit binding if one exists.
        service_name_lower = service_name.lower()
        if service_name_lower in _SERVICE_ERROR_NAMES:
            return _SERVICE_ERROR_NAMES[service_name_lower]

        # Attempt to retrieve the service name from the catalog.
        try:
            service_model = get_service_catalog().get(service_name)
            if service_model is not None:
                sfn_normalised_service_name = service_model.service_id.replace(" ", "")
                return sfn_normalised_service_name
        except UnknownServiceError:
            LOG.warning(
                "No service for name '%s' when building aws-sdk service error name.",
                service_name,
            )

        # Revert to returning the resource's service name and log the missing binding.
        LOG.error(
            "No normalised service error name for aws-sdk integration was found for service: '%s'",
            service_name,
        )
        return service_name

    @staticmethod
    def _normalise_exception_name(norm_service_name: str, ex: Exception) -> str:
        ex_name = ex.__class__.__name__
        norm_ex_name = (
            f"{norm_service_name}.{norm_service_name if ex_name == 'ClientError' else ex_name}"
        )
        if not norm_ex_name.endswith("Exception"):
            norm_ex_name += "Exception"
        return norm_ex_name

    def _get_task_failure_event(self, env: Environment, error: str, cause: str) -> FailureEvent:
        return FailureEvent(
            env=env,
            error_name=ErrorName(error_name=error),
            event_type=HistoryEventType.TaskFailed,
            event_details=EventDetails(
                taskFailedEventDetails=TaskFailedEventDetails(
                    resource=self._get_sfn_resource(),
                    resourceType=self._get_sfn_resource_type(),
                    error=error,
                    cause=cause,
                )
            ),
        )

    def _from_error(self, env: Environment, ex: Exception) -> FailureEvent:
        if isinstance(ex, ClientError):
            norm_service_name: str = self._normalise_service_error_name(self.resource.api_name)
            error: str = self._normalise_exception_name(norm_service_name, ex)

            error_message: str = ex.response["Error"]["Message"]
            cause_details = [
                f"Service: {norm_service_name}",
                f"Status Code: {ex.response['ResponseMetadata']['HTTPStatusCode']}",
                f"Request ID: {ex.response['ResponseMetadata']['RequestId']}",
            ]
            if "HostId" in ex.response["ResponseMetadata"]:
                cause_details.append(
                    f"Extended Request ID: {ex.response['ResponseMetadata']['HostId']}"
                )

            cause: str = f"{error_message} ({', '.join(cause_details)})"
            failure_event = self._get_task_failure_event(env=env, error=error, cause=cause)
            return failure_event
        return super()._from_error(env=env, ex=ex)

    def _eval_service_task(
        self,
        env: Environment,
        resource_runtime_part: ResourceRuntimePart,
        normalised_parameters: dict,
        state_credentials: StateCredentials,
    ):
        service_name = self._get_boto_service_name()
        api_action = self._get_boto_service_action()
        api_client = boto_client_for(
            service=service_name,
            region=resource_runtime_part.region,
            state_credentials=state_credentials,
        )
        response = getattr(api_client, api_action)(**normalised_parameters) or dict()
        if response:
            response.pop("ResponseMetadata", None)
        env.stack.append(response)
