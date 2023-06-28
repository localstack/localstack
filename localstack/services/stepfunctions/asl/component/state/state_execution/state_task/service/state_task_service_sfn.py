from typing import Any, Final, Optional

from botocore.config import Config
from botocore.exceptions import ClientError

from localstack.aws.api.stepfunctions import HistoryEventType, TaskFailedEventDetails
from localstack.services.stepfunctions.asl.component.common.error_name.custom_error_name import (
    CustomErrorName,
)
from localstack.services.stepfunctions.asl.component.common.error_name.failure_event import (
    FailureEvent,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.service.state_task_service_callback import (
    StateTaskServiceCallback,
)
from localstack.services.stepfunctions.asl.eval.callback.callback import CallbackOutcomeFailureError
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.services.stepfunctions.asl.eval.event.event_detail import EventDetails
from localstack.services.stepfunctions.asl.utils.encoding import to_json_str
from localstack.utils.aws import aws_stack
from localstack.utils.strings import camel_to_snake_case


class StateTaskServiceSfn(StateTaskServiceCallback):
    _ERROR_NAME_CLIENT: Final[str] = "SQS.TODO1"
    _ERROR_NAME_AWS: Final[str] = "SQS.TODO2"

    _SUPPORTED_API_PARAM_BINDINGS: Final[dict[str, set[str]]] = {
        "startexecution": {"Input", "Name", "StateMachineArn"}
    }

    _SFN_TO_BOTO_PARAM_NORMALISERS = {
        "startexecution": {"Input": "input", "Name": "name", "StateMachineArn": "stateMachineArn"}
    }

    _BOTO_TO_SFN_RESPONSE_BINDINGS = {
        "startexecution": {"startDate": "StartDate", "executionArn": "ExecutionArn"}
    }

    def _get_supported_parameters(self) -> Optional[set[str]]:
        return self._SUPPORTED_API_PARAM_BINDINGS.get(self.resource.api_action.lower())

    def _get_parameters_normalising_bindings(self) -> dict[str, str]:
        return self._SFN_TO_BOTO_PARAM_NORMALISERS.get(self.resource.api_action.lower(), dict())

    def _normalise_botocore_response(self, api_action: str, response: dict[str, Any]):
        overrides = self._BOTO_TO_SFN_RESPONSE_BINDINGS.get(api_action.lower())
        if overrides:
            for fault_key, key_override in overrides.items():
                if fault_key in response:
                    response[key_override] = response[fault_key]
                    del response[fault_key]

    def _from_error(self, env: Environment, ex: Exception) -> FailureEvent:
        if isinstance(ex, CallbackOutcomeFailureError):
            return self._get_callback_outcome_failure_event(ex=ex)
        if isinstance(ex, TimeoutError):
            return self._get_timed_out_failure_event()

        if isinstance(ex, ClientError):
            return FailureEvent(
                error_name=CustomErrorName(self._ERROR_NAME_CLIENT),
                event_type=HistoryEventType.TaskFailed,
                event_details=EventDetails(
                    taskFailedEventDetails=TaskFailedEventDetails(
                        error=self._ERROR_NAME_CLIENT,
                        cause=ex.response["Error"][
                            "Message"
                        ],  # TODO: update to report expected cause.
                        resource=self._get_sfn_resource(),
                        resourceType=self._get_sfn_resource_type(),
                    )
                ),
            )
        else:
            return FailureEvent(
                error_name=CustomErrorName(self._ERROR_NAME_AWS),
                event_type=HistoryEventType.TaskFailed,
                event_details=EventDetails(
                    taskFailedEventDetails=TaskFailedEventDetails(
                        error=self._ERROR_NAME_AWS,
                        cause=str(ex),  # TODO: update to report expected cause.
                        resource=self._get_sfn_resource(),
                        resourceType=self._get_sfn_resource_type(),
                    )
                ),
            )

    def _normalised_parameters_bindings(self, parameters: dict[str, str]) -> dict[str, str]:
        normalised_parameters = super()._normalised_parameters_bindings(parameters=parameters)

        if self.resource.api_action.lower() == "startexecution":
            optional_input = normalised_parameters.get("input")
            if not isinstance(optional_input, str):
                normalised_parameters["input"] = to_json_str(optional_input)

        return normalised_parameters

    def _eval_service_task(self, env: Environment, parameters: dict) -> None:
        api_action = camel_to_snake_case(self.resource.api_action)
        sfn_client = aws_stack.create_external_boto_client(
            "stepfunctions", config=Config(parameter_validation=False)
        )
        response = getattr(sfn_client, api_action)(**parameters)
        response.pop("ResponseMetadata", None)
        self._normalise_botocore_response(self.resource.api_action, response)
        env.stack.append(response)
