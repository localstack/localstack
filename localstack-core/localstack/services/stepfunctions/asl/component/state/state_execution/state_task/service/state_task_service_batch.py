from typing import Any, Callable, Final, Optional

from botocore.exceptions import ClientError
from moto.batch.utils import JobStatus

from localstack.aws.api.stepfunctions import HistoryEventType, TaskFailedEventDetails
from localstack.services.stepfunctions.asl.component.common.error_name.custom_error_name import (
    CustomErrorName,
)
from localstack.services.stepfunctions.asl.component.common.error_name.failure_event import (
    FailureEvent,
    FailureEventException,
)
from localstack.services.stepfunctions.asl.component.common.error_name.states_error_name import (
    StatesErrorName,
)
from localstack.services.stepfunctions.asl.component.common.error_name.states_error_name_type import (
    StatesErrorNameType,
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
    ResourceCondition.Sync,
}

_BATCH_JOB_TERMINATION_STATUS_SET: Final[set[JobStatus]] = {JobStatus.SUCCEEDED, JobStatus.FAILED}

_ENVIRONMENT_VARIABLE_MANAGED_BY_AWS: Final[str] = "MANAGED_BY_AWS"
_ENVIRONMENT_VARIABLE_MANAGED_BY_AWS_VALUE: Final[str] = "STARTED_BY_STEP_FUNCTIONS"

_SUPPORTED_API_PARAM_BINDINGS: Final[dict[str, set[str]]] = {
    "submitjob": {
        "ArrayProperties",
        "ContainerOverrides",
        "DependsOn",
        "JobDefinition",
        "JobName",
        "JobQueue",
        "Parameters",
        "RetryStrategy",
        "Timeout",
        "Tags",
    }
}


class StateTaskServiceBatch(StateTaskServiceCallback):
    def __init__(self):
        super().__init__(supported_integration_patterns=_SUPPORTED_INTEGRATION_PATTERNS)

    def _get_supported_parameters(self) -> Optional[set[str]]:
        return _SUPPORTED_API_PARAM_BINDINGS.get(self.resource.api_action.lower())

    @staticmethod
    def _attach_aws_environment_variables(parameters: dict) -> None:
        # Attaches to the ContainerOverrides environment variables the AWS managed flags.
        container_overrides = parameters.get("ContainerOverrides")
        if container_overrides is None:
            container_overrides = dict()
            parameters["ContainerOverrides"] = container_overrides

        environment = container_overrides.get("Environment")
        if environment is None:
            environment = list()
            container_overrides["Environment"] = environment

        environment.append(
            {
                "name": _ENVIRONMENT_VARIABLE_MANAGED_BY_AWS,
                "value": _ENVIRONMENT_VARIABLE_MANAGED_BY_AWS_VALUE,
            }
        )

    def _before_eval_execution(
        self, env: Environment, resource_runtime_part: ResourceRuntimePart, raw_parameters: dict
    ) -> None:
        if self.resource.condition == ResourceCondition.Sync:
            self._attach_aws_environment_variables(parameters=raw_parameters)
        super()._before_eval_execution(
            env=env, resource_runtime_part=resource_runtime_part, raw_parameters=raw_parameters
        )

    def _from_error(self, env: Environment, ex: Exception) -> FailureEvent:
        if isinstance(ex, ClientError):
            error_code = ex.response["Error"]["Code"]
            error_name = f"Batch.{error_code}"
            status_code = ex.response["ResponseMetadata"]["HTTPStatusCode"]
            error_message = ex.response["Error"]["Message"]
            request_id = ex.response["ResponseMetadata"]["RequestId"]
            response_details = "; ".join(
                [
                    "Service: AWSBatch",
                    f"Status Code: {status_code}",
                    f"Error Code: {error_code}",
                    f"Request ID: {request_id}",
                    "Proxy: null",
                ]
            )
            cause = f"Error executing request, Exception : {error_message}, RequestId: {request_id} ({response_details})"
            return FailureEvent(
                env=env,
                error_name=CustomErrorName(error_name),
                event_type=HistoryEventType.TaskFailed,
                event_details=EventDetails(
                    taskFailedEventDetails=TaskFailedEventDetails(
                        error=error_name,
                        cause=cause,
                        resource=self._get_sfn_resource(),
                        resourceType=self._get_sfn_resource_type(),
                    )
                ),
            )
        return super()._from_error(env=env, ex=ex)

    def _build_sync_resolver(
        self,
        env: Environment,
        resource_runtime_part: ResourceRuntimePart,
        normalised_parameters: dict,
    ) -> Callable[[], Optional[Any]]:
        batch_client = boto_client_for(
            region=resource_runtime_part.region,
            account=resource_runtime_part.account,
            service="batch",
        )
        submission_output: dict = env.stack.pop()
        job_id = submission_output["JobId"]

        def _sync_resolver() -> Optional[dict]:
            describe_jobs_response = batch_client.describe_jobs(jobs=[job_id])
            describe_jobs = describe_jobs_response["jobs"]
            if describe_jobs:
                describe_job = describe_jobs[0]
                describe_job_status: JobStatus = describe_job["status"]
                # Add raise error if abnormal state
                if describe_job_status in _BATCH_JOB_TERMINATION_STATUS_SET:
                    self._normalise_response(
                        response=describe_jobs_response, service_action_name="describe_jobs"
                    )
                    if describe_job_status == JobStatus.SUCCEEDED:
                        return describe_job

                    raise FailureEventException(
                        FailureEvent(
                            env=env,
                            error_name=StatesErrorName(typ=StatesErrorNameType.StatesTaskFailed),
                            event_type=HistoryEventType.TaskFailed,
                            event_details=EventDetails(
                                taskFailedEventDetails=TaskFailedEventDetails(
                                    resource=self._get_sfn_resource(),
                                    resourceType=self._get_sfn_resource_type(),
                                    error=StatesErrorNameType.StatesTaskFailed.to_name(),
                                    cause=to_json_str(describe_job),
                                )
                            ),
                        )
                    )
            return None

        return _sync_resolver

    def _eval_service_task(
        self,
        env: Environment,
        resource_runtime_part: ResourceRuntimePart,
        normalised_parameters: dict,
    ):
        service_name = self._get_boto_service_name()
        api_action = self._get_boto_service_action()
        batch_client = boto_client_for(
            region=resource_runtime_part.region,
            account=resource_runtime_part.account,
            service=service_name,
        )
        response = getattr(batch_client, api_action)(**normalised_parameters)
        response.pop("ResponseMetadata", None)
        env.stack.append(response)
