from typing import Any, Callable, Final, Optional

from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.service.resource import (
    ResourceCondition,
    ResourceRuntimePart,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.service.state_task_service_callback import (
    StateTaskServiceCallback,
)
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.services.stepfunctions.asl.utils.boto_client import boto_client_for

_SUPPORTED_INTEGRATION_PATTERNS: Final[set[ResourceCondition]] = {
    ResourceCondition.WaitForTaskToken,
    ResourceCondition.Sync,
}

_SUPPORTED_API_PARAM_BINDINGS: Final[dict[str, set[str]]] = {
    "runtask": {
        "Cluster",
        "Group",
        "LaunchType",
        "NetworkConfiguration",
        "Overrides",
        "PlacementConstraints",
        "PlacementStrategy",
        "PlatformVersion",
        "PropagateTags",
        "TaskDefinition",
        "EnableExecuteCommand",
    }
}

_STARTED_BY_PARAMETER_RAW_KEY: Final[str] = "StartedBy"
_STARTED_BY_PARAMETER_VALUE: Final[str] = "AWS Step Functions"


class StateTaskServiceEcs(StateTaskServiceCallback):
    def __init__(self):
        super().__init__(supported_integration_patterns=_SUPPORTED_INTEGRATION_PATTERNS)

    def _get_supported_parameters(self) -> Optional[set[str]]:
        return _SUPPORTED_API_PARAM_BINDINGS.get(self.resource.api_action.lower())

    def _before_eval_execution(
        self, env: Environment, resource_runtime_part: ResourceRuntimePart, raw_parameters: dict
    ) -> None:
        if self.resource.condition == ResourceCondition.Sync:
            raw_parameters[_STARTED_BY_PARAMETER_RAW_KEY] = _STARTED_BY_PARAMETER_VALUE
        super()._before_eval_execution(
            env=env, resource_runtime_part=resource_runtime_part, raw_parameters=raw_parameters
        )

    def _eval_service_task(
        self,
        env: Environment,
        resource_runtime_part: ResourceRuntimePart,
        normalised_parameters: dict,
    ):
        service_name = self._get_boto_service_name()
        api_action = self._get_boto_service_action()
        ecs_client = boto_client_for(
            region=resource_runtime_part.region,
            account=resource_runtime_part.account,
            service=service_name,
        )
        response = getattr(ecs_client, api_action)(**normalised_parameters)
        response.pop("ResponseMetadata", None)

        # AWS outputs the description of the task, not the output of run_task.
        match self._get_boto_service_action():
            case "run_task":
                self._normalise_response(response=response, service_action_name="run_task")
                cluster_arn: str = response["Tasks"][0]["ClusterArn"]
                task_arn: str = response["Tasks"][0]["TaskArn"]
                describe_tasks_output = ecs_client.describe_tasks(
                    cluster=cluster_arn, tasks=[task_arn]
                )
                describe_tasks_output.pop("ResponseMetadata", None)
                self._normalise_response(
                    response=describe_tasks_output, service_action_name="describe_tasks"
                )
                env.stack.append(describe_tasks_output)
                return

        env.stack.append(response)

    def _build_sync_resolver(
        self,
        env: Environment,
        resource_runtime_part: ResourceRuntimePart,
        normalised_parameters: dict,
    ) -> Callable[[], Optional[Any]]:
        ecs_client = boto_client_for(
            region=resource_runtime_part.region,
            account=resource_runtime_part.account,
            service="ecs",
        )
        submission_output: dict = env.stack.pop()
        task_arn: str = submission_output["Tasks"][0]["TaskArn"]
        cluster_arn: str = submission_output["Tasks"][0]["ClusterArn"]

        def _sync_resolver() -> Optional[dict]:
            describe_tasks_output = ecs_client.describe_tasks(cluster=cluster_arn, tasks=[task_arn])
            last_status: str = describe_tasks_output["tasks"][0]["lastStatus"]

            if last_status == "STOPPED":
                self._normalise_response(
                    response=describe_tasks_output, service_action_name="describe_tasks"
                )
                return describe_tasks_output["Tasks"][0]  # noqa

            return None

        return _sync_resolver
