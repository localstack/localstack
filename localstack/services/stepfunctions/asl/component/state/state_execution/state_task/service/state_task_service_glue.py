from typing import Callable, Final

import boto3
from botocore.exceptions import ClientError

from localstack.aws.api.stepfunctions import HistoryEventType, TaskFailedEventDetails
from localstack.services.stepfunctions.asl.component.common.error_name.custom_error_name import (
    CustomErrorName,
)
from localstack.services.stepfunctions.asl.component.common.error_name.failure_event import (
    FailureEvent,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.service.resource import (
    ResourceRuntimePart,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.service.state_task_service_callback import (
    StateTaskServiceCallback,
)
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.services.stepfunctions.asl.eval.event.event_detail import EventDetails
from localstack.services.stepfunctions.asl.utils.boto_client import boto_client_for

_HANDLER_REFLECTION_PREFIX: Final[str] = "_handle_"
_SYNC_HANDLER_REFLECTION_PREFIX: Final[str] = "_sync_to_"
_API_ACTION_HANDLER_TYPE = Callable[[Environment, ResourceRuntimePart, dict], None]


class StateTaskServiceGlue(StateTaskServiceCallback):
    def _get_handler_by_reflection(self, prefix: str) -> _API_ACTION_HANDLER_TYPE:
        api_action = self._get_boto_service_action()
        handler_name = prefix + api_action
        resolver_handler = getattr(self, handler_name)
        if resolver_handler is None:
            raise ValueError(f"Unknown or unsupported glue action '{api_action}'.")
        return resolver_handler

    def _get_api_action_handler(self) -> _API_ACTION_HANDLER_TYPE:
        return self._get_handler_by_reflection(_HANDLER_REFLECTION_PREFIX)

    def _get_api_action_sync_handler(self) -> _API_ACTION_HANDLER_TYPE:
        return self._get_handler_by_reflection(_SYNC_HANDLER_REFLECTION_PREFIX)

    @staticmethod
    def _get_glue_client(resource_runtime_part: ResourceRuntimePart) -> boto3.client:
        return boto_client_for(
            region=resource_runtime_part.region,
            account=resource_runtime_part.account,
            service="glue",
        )

    def _from_error(self, env: Environment, ex: Exception) -> FailureEvent:
        if isinstance(ex, ClientError):
            return FailureEvent(
                env=env,
                error_name=CustomErrorName("TODO"),
                event_type=HistoryEventType.TaskFailed,
                event_details=EventDetails(
                    taskFailedEventDetails=TaskFailedEventDetails(
                        error="TODO",
                        cause=ex.response["Error"]["Message"],
                        resource=self._get_sfn_resource(),
                        resourceType=self._get_sfn_resource_type(),
                    )
                ),
            )
        return super()._from_error(env=env, ex=ex)

    def _handle_start_job_run(
        self,
        env: Environment,
        resource_runtime_part: ResourceRuntimePart,
        normalised_parameters: dict,
    ):
        glue_client = self._get_glue_client(resource_runtime_part=resource_runtime_part)
        response = glue_client.start_job_run(**normalised_parameters)
        response.pop("ResponseMetadata", None)
        # AWS StepFunctions appends to the output the JobName. This is a required field for start_job_run, hence the
        # access at this depth is safe.
        response["JobName"] = normalised_parameters.get("JobName")
        env.stack.append(response)

    def _eval_service_task(
        self,
        env: Environment,
        resource_runtime_part: ResourceRuntimePart,
        normalised_parameters: dict,
    ):
        api_action_handler = self._get_api_action_handler()
        api_action_handler(env, resource_runtime_part, normalised_parameters)

    def _sync_to_start_job_run(self):
        # TODO: Implement this method
        pass

    def _sync(
        self,
        env: Environment,
        resource_runtime_part: ResourceRuntimePart,
        normalised_parameters: dict,
    ) -> None:
        sync_handler = self._get_api_action_sync_handler()
        sync_handler(env, resource_runtime_part, normalised_parameters)
