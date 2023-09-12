import json
from typing import Final, Optional

from botocore.config import Config

from localstack.aws.api.stepfunctions import HistoryEventType, TaskFailedEventDetails
from localstack.aws.connect import connect_externally_to
from localstack.services.stepfunctions.asl.component.common.error_name.custom_error_name import (
    CustomErrorName,
)
from localstack.services.stepfunctions.asl.component.common.error_name.error_name import ErrorName
from localstack.services.stepfunctions.asl.component.common.error_name.failure_event import (
    FailureEvent,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.service.state_task_service_callback import (
    StateTaskServiceCallback,
)
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.services.stepfunctions.asl.eval.event.event_detail import EventDetails
from localstack.services.stepfunctions.asl.utils.encoding import to_json_str
from localstack.utils.strings import camel_to_snake_case


class SfnFailedEntryCountException(RuntimeError):
    cause: Final[Optional[dict]]

    def __init__(self, cause: Optional[dict]):
        super().__init__(json.dumps(cause))
        self.cause = cause


class StateTaskServiceEvents(StateTaskServiceCallback):
    _FAILED_ENTRY_ERROR_NAME: Final[ErrorName] = CustomErrorName(
        error_name="EventBridge.FailedEntry"
    )

    _SUPPORTED_API_PARAM_BINDINGS: Final[dict[str, set[str]]] = {"putevents": {"Entries"}}

    def _get_supported_parameters(self) -> Optional[set[str]]:
        return self._SUPPORTED_API_PARAM_BINDINGS.get(self.resource.api_action.lower())

    def _from_error(self, env: Environment, ex: Exception) -> FailureEvent:
        if isinstance(ex, SfnFailedEntryCountException):
            return FailureEvent(
                error_name=self._FAILED_ENTRY_ERROR_NAME,
                event_type=HistoryEventType.TaskFailed,
                event_details=EventDetails(
                    taskFailedEventDetails=TaskFailedEventDetails(
                        error=self._FAILED_ENTRY_ERROR_NAME.error_name,
                        cause=ex.cause,
                        resource=self._get_sfn_resource(),
                        resourceType=self._get_sfn_resource_type(),
                    )
                ),
            )
        return super()._from_error(env=env, ex=ex)

    @staticmethod
    def _normalised_request_parameters(env: Environment, parameters: dict):
        entries = parameters.get("Entries", [])
        for entry in entries:
            # Optimised integration for events automatically stringifies "Entries.Detail" if this is not a string,
            #  and only if these are json objects.
            if "Detail" in entry:
                detail = entry.get("Detail")
                if isinstance(detail, dict):
                    entry["Detail"] = to_json_str(detail)  # Pass runtime error upstream.

            # The execution ARN and the state machine ARN are automatically appended to the Resources
            #  field of each PutEventsRequestEntry.
            resources = entry.get("Resources", [])
            resources.append(env.context_object_manager.context_object["StateMachine"]["Id"])
            resources.append(env.context_object_manager.context_object["Execution"]["Id"])
            entry["Resources"] = resources

    def _eval_service_task(self, env: Environment, parameters: dict) -> None:
        self._normalised_request_parameters(env=env, parameters=parameters)
        api_action = camel_to_snake_case(self.resource.api_action)
        events_client = connect_externally_to(config=Config(parameter_validation=False)).events
        response = getattr(events_client, api_action)(**parameters)
        response.pop("ResponseMetadata", None)

        # If the response from PutEvents contains a non-zero FailedEntryCount then the
        #  Task state fails with the error EventBridge.FailedEntry.
        if self.resource.api_action == "putevents":
            failed_entry_count = response.get("FailedEntryCount", 0)
            if failed_entry_count > 0:
                # TODO: pipe events' cause in the exception object. At them moment
                #  LS events does not update this field.
                raise SfnFailedEntryCountException(cause={"Cause": "Unsupported"})

        env.stack.append(response)
