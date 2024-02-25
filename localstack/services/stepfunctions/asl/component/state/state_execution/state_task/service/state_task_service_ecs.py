from typing import Final, Optional

from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.service.resource import (
    ResourceCondition,
    ResourceRuntimePart,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.service.state_task_service_callback import (
    StateTaskServiceCallback,
)
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.services.stepfunctions.asl.utils.boto_client import boto_client_for


class StateTaskServiceEcs(StateTaskServiceCallback):
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

    def _get_supported_parameters(self) -> Optional[set[str]]:
        return self._SUPPORTED_API_PARAM_BINDINGS.get(self.resource.api_action.lower())

    # def _from_error(self, env: Environment, ex: Exception) -> FailureEvent:
    #     if isinstance(ex, ClientError):
    #         error_code = ex.response["Error"]["Code"]
    #         error_name: str = f"StepFunctions.{error_code}Exception"
    #         error_cause_details = [
    #             "Service: AWSStepFunctions",
    #             f"Status Code: {ex.response['ResponseMetadata']['HTTPStatusCode']}",
    #             f"Error Code: {error_code}",
    #             f"Request ID: {ex.response['ResponseMetadata']['RequestId']}",
    #             "Proxy: null",  # TODO: investigate this proxy value.
    #         ]
    #         if "HostId" in ex.response["ResponseMetadata"]:
    #             error_cause_details.append(
    #                 f'Extended Request ID: {ex.response["ResponseMetadata"]["HostId"]}'
    #             )
    #         error_cause: str = (
    #             f"{ex.response['Error']['Message']} ({'; '.join(error_cause_details)})"
    #         )
    #         return FailureEvent(
    #             error_name=CustomErrorName(error_name),
    #             event_type=HistoryEventType.TaskFailed,
    #             event_details=EventDetails(
    #                 taskFailedEventDetails=TaskFailedEventDetails(
    #                     error=error_name,
    #                     cause=error_cause,
    #                     resource=self._get_sfn_resource(),
    #                     resourceType=self._get_sfn_resource_type(),
    #                 )
    #             ),
    #         )
    #     return super()._from_error(env=env, ex=ex)

    def _before_eval_execution(
        self, env: Environment, resource_runtime_part: ResourceRuntimePart, raw_parameters: dict
    ) -> None:
        if self.resource.condition == ResourceCondition.Sync:
            raw_parameters[self._STARTED_BY_PARAMETER_RAW_KEY] = self._STARTED_BY_PARAMETER_VALUE
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

    def _sync_to_run_task(
        self,
        env: Environment,
        resource_runtime_part: ResourceRuntimePart,
    ) -> None:
        ...
        ecs_client = boto_client_for(
            region=resource_runtime_part.region,
            account=resource_runtime_part.account,
            service="ecs",
        )
        submission_output: dict = env.stack.pop()
        task_arn: str = submission_output["Tasks"][0]["TaskArn"]
        cluster_arn: str = submission_output["Tasks"][0]["ClusterArn"]

        def _has_terminated() -> Optional[dict]:
            describe_tasks_output = ecs_client.describe_tasks(cluster=cluster_arn, tasks=[task_arn])
            last_status: str = describe_tasks_output["tasks"][0]["lastStatus"]

            if last_status == "STOPPED":
                self._normalise_response(
                    response=describe_tasks_output, service_action_name="describe_tasks"
                )
                return describe_tasks_output["Tasks"][0]  # noqa

                # if execution_status == ExecutionStatus.SUCCEEDED:
                #     return describe_execution_output
                # else:
                #     raise FailureEventException(
                #         FailureEvent(
                #             error_name=StatesErrorName(typ=StatesErrorNameType.StatesTaskFailed),
                #             event_type=HistoryEventType.TaskFailed,
                #             event_details=EventDetails(
                #                 taskFailedEventDetails=TaskFailedEventDetails(
                #                     resource=self._get_sfn_resource(),
                #                     resourceType=self._get_sfn_resource_type(),
                #                     error=StatesErrorNameType.StatesTaskFailed.to_name(),
                #                     cause=to_json_str(describe_execution_output),
                #                 )
                #             ),
                #         )
                #     )
            return None

        termination_output: Optional[dict] = None
        while env.is_running() and termination_output is None:
            termination_output: Optional[dict] = _has_terminated()

        env.stack.append(termination_output)

    def _sync(
        self,
        env: Environment,
        resource_runtime_part: ResourceRuntimePart,
        normalised_parameters: dict,
    ) -> None:
        match self._get_boto_service_action():
            case "run_task":
                return self._sync_to_run_task(env=env, resource_runtime_part=resource_runtime_part)
            case _:
                super()._sync(
                    env=env,
                    resource_runtime_part=resource_runtime_part,
                    normalised_parameters=normalised_parameters,
                )
