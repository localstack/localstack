import json
from typing import Any, Final, Optional

from botocore.exceptions import ClientError

from localstack.aws.api.stepfunctions import (
    DescribeExecutionOutput,
    ExecutionStatus,
    HistoryEventType,
    TaskFailedEventDetails,
)
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
    ResourceRuntimePart,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.service.state_task_service_callback import (
    StateTaskServiceCallback,
)
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.services.stepfunctions.asl.eval.event.event_detail import EventDetails
from localstack.services.stepfunctions.asl.utils.boto_client import boto_client_for
from localstack.services.stepfunctions.asl.utils.encoding import to_json_str
from localstack.utils.collections import select_from_typed_dict
from localstack.utils.strings import camel_to_snake_case


class StateTaskServiceSfn(StateTaskServiceCallback):
    _SUPPORTED_API_PARAM_BINDINGS: Final[dict[str, set[str]]] = {
        "startexecution": {"Input", "Name", "StateMachineArn"}
    }

    _SFN_TO_BOTO_PARAM_NORMALISERS = {
        "startexecution": {"Input": "input", "Name": "name", "StateMachineArn": "stateMachineArn"}
    }

    _BOTO_TO_SFN_RESPONSE_BINDINGS = {
        "startexecution": ["StartDate", "ExecutionArn"],
        "describeexecution": [
            "ExecutionArn",
            "Input",
            ["InputDetails", ["Included"]],
            "Name",
            "Output",
            ["OutputDetails", ["Included"]],
            "StartDate",
            "StateMachineArn",
            "Status",
            "StopDate",
            "Error",
            "Cause",
        ],
    }

    def _get_supported_parameters(self) -> Optional[set[str]]:
        return self._SUPPORTED_API_PARAM_BINDINGS.get(self.resource.api_action.lower())

    def _get_parameters_normalising_bindings(self) -> dict[str, str]:
        return self._SFN_TO_BOTO_PARAM_NORMALISERS.get(self.resource.api_action.lower(), dict())

    def _normalise_botocore_response(self, api_action: str, response: dict[str, Any]) -> None:
        keys = self._BOTO_TO_SFN_RESPONSE_BINDINGS.get(api_action.lower())
        if keys is None:
            return

        def _build_lower_to_key_dict(key_list: list[str]) -> dict[str, Any]:
            lower_to_key_dict = dict()
            for key in key_list:
                if isinstance(key, str):
                    lower_to_key_dict[key.lower()] = key
                elif isinstance(key, list):
                    lower_to_key_dict[key[0].lower()] = [key[0], _build_lower_to_key_dict(key[1])]
            return lower_to_key_dict

        def _update_key(old_key, new_key, obj):
            if new_key != old_key:
                value_bind = obj[old_key]
                del obj[old_key]
                obj[new_key] = value_bind

        def _apply_normalisation(lookup_keys, dictionary):
            input_keys = list(dictionary.keys())
            for input_key in input_keys:
                normalised_key = lookup_keys.get(input_key.lower())
                if isinstance(normalised_key, str):
                    _update_key(input_key, normalised_key, dictionary)
                elif isinstance(normalised_key, list):
                    _update_key(input_key, normalised_key[0], dictionary)
                    _apply_normalisation(normalised_key[1], dictionary[normalised_key[0]])

        lower_to_normalise_key = _build_lower_to_key_dict(keys)
        _apply_normalisation(lower_to_normalise_key, response)

    def _from_error(self, env: Environment, ex: Exception) -> FailureEvent:
        if isinstance(ex, ClientError):
            error_code = ex.response["Error"]["Code"]
            error_name: str = f"StepFunctions.{error_code}Exception"
            error_cause_details = [
                "Service: AWSStepFunctions",
                f"Status Code: {ex.response['ResponseMetadata']['HTTPStatusCode']}",
                f"Error Code: {error_code}",
                f"Request ID: {ex.response['ResponseMetadata']['RequestId']}",
                "Proxy: null",  # TODO: investigate this proxy value.
            ]
            if "HostId" in ex.response["ResponseMetadata"]:
                error_cause_details.append(
                    f'Extended Request ID: {ex.response["ResponseMetadata"]["HostId"]}'
                )
            error_cause: str = (
                f"{ex.response['Error']['Message']} ({'; '.join(error_cause_details)})"
            )
            return FailureEvent(
                error_name=CustomErrorName(error_name),
                event_type=HistoryEventType.TaskFailed,
                event_details=EventDetails(
                    taskFailedEventDetails=TaskFailedEventDetails(
                        error=error_name,
                        cause=error_cause,
                        resource=self._get_sfn_resource(),
                        resourceType=self._get_sfn_resource_type(),
                    )
                ),
            )
        return super()._from_error(env=env, ex=ex)

    def _normalised_parameters_bindings(self, raw_parameters: dict[str, str]) -> dict[str, str]:
        normalised_parameters = super()._normalised_parameters_bindings(
            raw_parameters=raw_parameters
        )

        if self.resource.api_action.lower() == "startexecution":
            optional_input = normalised_parameters.get("input")
            if not isinstance(optional_input, str):

                # AWS Sfn's documentation states:
                # If you don't include any JSON input data, you still must include the two braces.
                if optional_input is None:
                    optional_input = {}

                normalised_parameters["input"] = to_json_str(optional_input, separators=(",", ":"))

        return normalised_parameters

    @staticmethod
    def _sync2_api_output_of(typ: type, value: json) -> None:
        def _replace_with_json_if_str(key: str) -> None:
            inner_value = value.get(key)
            if isinstance(inner_value, str):
                value[key] = json.loads(inner_value)

        match typ:
            case DescribeExecutionOutput:  # noqa
                _replace_with_json_if_str("input")
                _replace_with_json_if_str("output")

    def _eval_service_task(
        self,
        env: Environment,
        resource_runtime_part: ResourceRuntimePart,
        normalised_parameters: dict,
    ):
        api_action = camel_to_snake_case(self.resource.api_action)
        sfn_client = boto_client_for(
            region=resource_runtime_part.region,
            account=resource_runtime_part.account,
            service="stepfunctions",
        )
        response = getattr(sfn_client, api_action)(**normalised_parameters)
        response.pop("ResponseMetadata", None)
        self._normalise_botocore_response(self.resource.api_action, response)
        env.stack.append(response)

    def _sync_to_start_machine(
        self,
        env: Environment,
        resource_runtime_part: ResourceRuntimePart,
        sync2_response: bool,
    ) -> None:
        sfn_client = boto_client_for(
            region=resource_runtime_part.region,
            account=resource_runtime_part.account,
            service="stepfunctions",
        )
        submission_output: dict = env.stack.pop()
        execution_arn: str = submission_output["ExecutionArn"]

        def _has_terminated() -> Optional[dict]:
            describe_execution_output = sfn_client.describe_execution(executionArn=execution_arn)
            describe_execution_output: DescribeExecutionOutput = select_from_typed_dict(
                DescribeExecutionOutput, describe_execution_output
            )
            execution_status: ExecutionStatus = describe_execution_output["status"]

            if execution_status != ExecutionStatus.RUNNING:
                if sync2_response:
                    self._sync2_api_output_of(
                        typ=DescribeExecutionOutput, value=describe_execution_output
                    )
                self._normalise_botocore_response("describeexecution", describe_execution_output)
                if execution_status == ExecutionStatus.SUCCEEDED:
                    return describe_execution_output
                else:
                    raise FailureEventException(
                        FailureEvent(
                            error_name=StatesErrorName(typ=StatesErrorNameType.StatesTaskFailed),
                            event_type=HistoryEventType.TaskFailed,
                            event_details=EventDetails(
                                taskFailedEventDetails=TaskFailedEventDetails(
                                    resource=self._get_sfn_resource(),
                                    resourceType=self._get_sfn_resource_type(),
                                    error=StatesErrorNameType.StatesTaskFailed.to_name(),
                                    cause=to_json_str(describe_execution_output),
                                )
                            ),
                        )
                    )
            return None

        termination_output: Optional[dict] = None
        while env.is_running() and not termination_output:
            termination_output: Optional[dict] = _has_terminated()

        env.stack.append(termination_output)

    def _sync(
        self,
        env: Environment,
        resource_runtime_part: ResourceRuntimePart,
        normalised_parameters: dict,
    ) -> None:
        match self.resource.api_action.lower():
            case "startexecution":
                self._sync_to_start_machine(
                    env=env, resource_runtime_part=resource_runtime_part, sync2_response=False
                )
            case _:
                super()._sync(env=env)

    def _sync2(
        self,
        env: Environment,
        resource_runtime_part: ResourceRuntimePart,
        normalised_parameters: dict,
    ) -> None:
        match self.resource.api_action.lower():
            case "startexecution":
                self._sync_to_start_machine(
                    env=env, resource_runtime_part=resource_runtime_part, sync2_response=True
                )
            case _:
                super()._sync2(env=env)
