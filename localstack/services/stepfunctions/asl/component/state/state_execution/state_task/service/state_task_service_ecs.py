from typing import Final, Optional

from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.service.resource import (
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

    # def _normalise_parameters(
    #         self,
    #         parameters: dict,
    #         boto_service_name: Optional[str] = None,
    #         service_action_name: Optional[str] = None,
    # ) -> None:
    #     if service_action_name is None:
    #         if self._get_boto_service_action() == "start_execution":
    #             optional_input = parameters.get("Input")
    #             if not isinstance(optional_input, str):
    #                 # AWS Sfn's documentation states:
    #                 # If you don't include any JSON input data, you still must include the two braces.
    #                 if optional_input is None:
    #                     optional_input = {}
    #                 parameters["Input"] = to_json_str(optional_input, separators=(",", ":"))
    #     super()._normalise_parameters(
    #         parameters=parameters,
    #         boto_service_name=boto_service_name,
    #         service_action_name=service_action_name,
    #     )

    def _eval_service_task(
        self,
        env: Environment,
        resource_runtime_part: ResourceRuntimePart,
        normalised_parameters: dict,
    ):
        service_name = self._get_boto_service_name()
        api_action = self._get_boto_service_action()
        client = boto_client_for(
            region=resource_runtime_part.region,
            account=resource_runtime_part.account,
            service=service_name,
        )
        response = getattr(client, api_action)(**normalised_parameters)
        response.pop("ResponseMetadata", None)
        env.stack.append(response)

    def _sync_to_run_task(
        self,
        env: Environment,
        resource_runtime_part: ResourceRuntimePart,
    ) -> None:
        ...
        # ecs_client = boto_client_for(
        #     region=resource_runtime_part.region,
        #     account=resource_runtime_part.account,
        #     service="ecs",
        # )

        # submission_output: dict = env.stack.pop()
        # TODO
        # execution_arn: str = submission_output["ExecutionArn"]

        def _has_terminated() -> Optional[dict]:
            return {}
            # connect_to().ecs.describe_tasks(cluster="", tasks=[])['tasks']
            # connect_to().ecs.run_task()['tasks'][0]['']
            # describe_execution_output = sfn_client.describe_execution(executionArn=execution_arn)
            # describe_execution_output: DescribeExecutionOutput = select_from_typed_dict(
            #     DescribeExecutionOutput, describe_execution_output
            # )
            # execution_status: ExecutionStatus = describe_execution_output["status"]
            #
            # if execution_status != ExecutionStatus.RUNNING:
            #     if sync2_response:
            #         self._sync2_api_output_of(
            #             typ=DescribeExecutionOutput, value=describe_execution_output
            #         )
            #     self._normalise_response(
            #         response=describe_execution_output, service_action_name="describe_execution"
            #     )
            #     if execution_status == ExecutionStatus.SUCCEEDED:
            #         return describe_execution_output
            #     else:
            #         raise FailureEventException(
            #             FailureEvent(
            #                 error_name=StatesErrorName(typ=StatesErrorNameType.StatesTaskFailed),
            #                 event_type=HistoryEventType.TaskFailed,
            #                 event_details=EventDetails(
            #                     taskFailedEventDetails=TaskFailedEventDetails(
            #                         resource=self._get_sfn_resource(),
            #                         resourceType=self._get_sfn_resource_type(),
            #                         error=StatesErrorNameType.StatesTaskFailed.to_name(),
            #                         cause=to_json_str(describe_execution_output),
            #                     )
            #                 ),
            #             )
            #         )
            # return None

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
