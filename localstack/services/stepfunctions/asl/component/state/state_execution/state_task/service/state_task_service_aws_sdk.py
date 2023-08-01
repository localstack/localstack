from botocore.config import Config
from botocore.exceptions import ClientError

from localstack.aws.api.stepfunctions import HistoryEventType, TaskFailedEventDetails
from localstack.aws.connect import connect_externally_to
from localstack.aws.protocol.service_router import get_service_catalog
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
from localstack.services.stepfunctions.asl.component.state.state_props import StateProps
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.services.stepfunctions.asl.eval.event.event_detail import EventDetails
from localstack.utils.common import camel_to_snake_case


class StateTaskServiceAwsSdk(StateTaskServiceCallback):
    _NORMALISED_SERVICE_NAMES = {"dynamodb": "DynamoDb"}
    _API_NAMES: dict[str, str] = {"sfn": "stepfunctions"}
    _SFN_TO_BOTO_PARAM_NORMALISERS = {
        "stepfunctions": {
            "send_task_success": {"Output": "output", "TaskToken": "taskToken"},
            "send_task_heartbeat": {"TaskToken": "taskToken"},
            "send_task_failure": {"TaskToken": "taskToken", "Error": "error", "Cause": "cause"},
        }
    }

    _normalised_api_name: str
    _normalised_api_action: str

    def from_state_props(self, state_props: StateProps) -> None:
        super().from_state_props(state_props=state_props)
        self._normalised_api_name = self._normalise_api_name(self.resource.api_name)
        self._normalised_api_action = camel_to_snake_case(self.resource.api_action)

    def _get_parameters_normalising_bindings(self) -> dict[str, str]:
        api_normalisers = self._SFN_TO_BOTO_PARAM_NORMALISERS.get(self._normalised_api_name, dict())
        action_normalisers = api_normalisers.get(self._normalised_api_action, dict())
        return action_normalisers

    def _get_sfn_resource_type(self) -> str:
        return f"{self.resource.service_name}:{self.resource.api_name}"

    def _normalise_api_name(self, api_name: str) -> str:
        return self._API_NAMES.get(api_name, api_name)

    @staticmethod
    def _normalise_service_name(service_name: str) -> str:
        service_name_lower = service_name.lower()
        if service_name_lower in StateTaskServiceAwsSdk._NORMALISED_SERVICE_NAMES:
            return StateTaskServiceAwsSdk._NORMALISED_SERVICE_NAMES[service_name_lower]
        return get_service_catalog().get(service_name).service_id.replace(" ", "")

    @staticmethod
    def _normalise_exception_name(norm_service_name: str, ex: Exception) -> str:
        ex_name = ex.__class__.__name__
        norm_ex_name = (
            f"{norm_service_name}.{norm_service_name if ex_name == 'ClientError' else ex_name}"
        )
        if not norm_ex_name.endswith("Exception"):
            norm_ex_name += "Exception"
        return norm_ex_name

    def _get_task_failure_event(self, error: str, cause: str) -> FailureEvent:
        return FailureEvent(
            error_name=StatesErrorName(typ=StatesErrorNameType.StatesTaskFailed),
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
            norm_service_name: str = self._normalise_service_name(self.resource.api_name)
            error: str = self._normalise_exception_name(norm_service_name, ex)

            error_message: str = ex.response["Error"]["Message"]
            cause_details = [
                f"Service: {norm_service_name}",
                f"Status Code: {ex.response['ResponseMetadata']['HTTPStatusCode']}",
                f"Request ID: {ex.response['ResponseMetadata']['RequestId']}",
            ]
            if "HostId" in ex.response["ResponseMetadata"]:
                cause_details.append(
                    f'Extended Request ID: {ex.response["ResponseMetadata"]["HostId"]}'
                )

            cause: str = f"{error_message} ({', '.join(cause_details)})"
            failure_event = self._get_task_failure_event(error=error, cause=cause)
            return failure_event
        return super()._from_error(env=env, ex=ex)

    def _eval_service_task(self, env: Environment, parameters: dict) -> None:
        api_client = connect_externally_to.get_client(
            service_name=self._normalised_api_name, config=Config(parameter_validation=False)
        )
        response = getattr(api_client, self._normalised_api_action)(**parameters) or dict()
        if response:
            response.pop("ResponseMetadata", None)
        env.stack.append(response)
