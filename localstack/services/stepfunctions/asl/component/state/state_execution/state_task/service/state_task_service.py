from __future__ import annotations

import abc
import copy
from typing import Any, Final, Optional

from botocore.model import OperationModel, StructureShape

from localstack.aws.api.stepfunctions import (
    HistoryEventExecutionDataDetails,
    HistoryEventType,
    TaskScheduledEventDetails,
    TaskStartedEventDetails,
    TaskSucceededEventDetails,
    TaskTimedOutEventDetails,
)
from localstack.aws.spec import load_service
from localstack.services.stepfunctions.asl.component.common.error_name.failure_event import (
    FailureEvent,
)
from localstack.services.stepfunctions.asl.component.common.error_name.states_error_name import (
    StatesErrorName,
)
from localstack.services.stepfunctions.asl.component.common.error_name.states_error_name_type import (
    StatesErrorNameType,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.service.resource import (
    ResourceRuntimePart,
    ServiceResource,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.state_task import (
    StateTask,
)
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.services.stepfunctions.asl.eval.event.event_detail import EventDetails
from localstack.services.stepfunctions.asl.utils.encoding import to_json_str
from localstack.utils.strings import camel_to_snake_case, snake_to_camel_case


class StateTaskService(StateTask, abc.ABC):
    resource: ServiceResource

    _SERVICE_NAME_SFN_TO_BOTO_OVERRIDES: Final[dict[str, str]] = {
        "sfn": "stepfunctions",
        "states": "stepfunctions",
    }

    def _get_sfn_resource(self) -> str:
        return self.resource.api_action

    def _get_sfn_resource_type(self) -> str:
        return self.resource.service_name

    def _get_timed_out_failure_event(self) -> FailureEvent:
        return FailureEvent(
            error_name=StatesErrorName(typ=StatesErrorNameType.StatesTimeout),
            event_type=HistoryEventType.TaskTimedOut,
            event_details=EventDetails(
                taskTimedOutEventDetails=TaskTimedOutEventDetails(
                    resourceType=self._get_sfn_resource_type(),
                    resource=self._get_sfn_resource(),
                    error=StatesErrorNameType.StatesTimeout.to_name(),
                )
            ),
        )

    @staticmethod
    def _get_boto_operation_model(
        boto_service_name: str, service_action_name: str
    ) -> OperationModel:
        norm_service_action_name = camel_to_snake_case(service_action_name)

        service = load_service(service=boto_service_name)

        boto_operation_names = {
            camel_to_snake_case(operation_name): operation_name
            for operation_name in service.operation_names
        }  # noqa
        boto_operation_name = boto_operation_names.get(norm_service_action_name)
        if boto_operation_name is None:
            raise RuntimeError(
                f"No api action named '{service_action_name}' available for service '{boto_service_name}'."
            )

        operation_model = service.operation_model(boto_operation_name)
        return operation_model

    def _to_boto_args(self, parameters: dict, structure_shape: StructureShape) -> None:
        shape_members = structure_shape.members
        norm_member_binds: dict[str, tuple[str, Optional[StructureShape]]] = {
            camel_to_snake_case(member_key): (
                member_key,
                member_value if isinstance(member_value, StructureShape) else None,
            )
            for member_key, member_value in shape_members.items()
        }
        parameters_bind_keys: list[str] = list(parameters.keys())
        for parameter_key in parameters_bind_keys:
            norm_parameter_key = camel_to_snake_case(parameter_key)
            norm_member_bind: Optional[
                tuple[str, Optional[StructureShape]]
            ] = norm_member_binds.get(norm_parameter_key)
            if norm_member_bind is not None:
                norm_member_bind_key, norm_member_bind_shape = norm_member_bind
                parameter_value = parameters.pop(parameter_key)
                if norm_member_bind_shape is not None:
                    self._to_boto_args(parameter_value, norm_member_bind_shape)
                parameters[norm_member_bind_key] = parameter_value

    @staticmethod
    def _to_sfn_cased(member_key: str) -> str:
        # Normalise the string to snake case, e.g. "HelloWorld_hello__world" -> "hello_world_hello_world"
        norm_member_key = camel_to_snake_case(member_key)
        # Normalise the snake case to camel case, e.g. "hello_world_hello_world" -> "HelloWorldHelloWorld"
        norm_member_key = snake_to_camel_case(norm_member_key)
        return norm_member_key

    def _from_boto_response(self, response: Any, structure_shape: StructureShape) -> None:
        if not isinstance(response, dict):
            return

        shape_members = structure_shape.members
        response_bind_keys: list[str] = list(response.keys())
        for response_key in response_bind_keys:
            norm_response_key = self._to_sfn_cased(response_key)
            if response_key in shape_members:
                shape_member = shape_members[response_key]

                response_value = response.pop(response_key)
                if isinstance(shape_member, StructureShape):
                    self._from_boto_response(response_value, shape_member)
                response[norm_response_key] = response_value

    def _get_boto_service_name(self, boto_service_name: Optional[str] = None) -> str:
        api_name = boto_service_name or self.resource.api_name
        return self._SERVICE_NAME_SFN_TO_BOTO_OVERRIDES.get(api_name, api_name)

    def _get_boto_service_action(self, service_action_name: Optional[str] = None) -> str:
        api_action = service_action_name or self.resource.api_action
        return camel_to_snake_case(api_action)

    def _normalise_parameters(
        self,
        parameters: dict,
        boto_service_name: Optional[str] = None,
        service_action_name: Optional[str] = None,
    ) -> None:
        boto_service_name = self._get_boto_service_name(boto_service_name=boto_service_name)
        service_action_name = self._get_boto_service_action(service_action_name=service_action_name)
        input_shape = self._get_boto_operation_model(
            boto_service_name=boto_service_name, service_action_name=service_action_name
        ).input_shape
        if input_shape is not None:
            self._to_boto_args(parameters, input_shape)  # noqa

    def _normalise_response(
        self,
        response: Any,
        boto_service_name: Optional[str] = None,
        service_action_name: Optional[str] = None,
    ) -> None:
        boto_service_name = self._get_boto_service_name(boto_service_name=boto_service_name)
        service_action_name = self._get_boto_service_action(service_action_name=service_action_name)
        output_shape = self._get_boto_operation_model(
            boto_service_name=boto_service_name, service_action_name=service_action_name
        ).output_shape
        if output_shape is not None:
            self._from_boto_response(response, output_shape)  # noqa

    @abc.abstractmethod
    def _eval_service_task(
        self,
        env: Environment,
        resource_runtime_part: ResourceRuntimePart,
        normalised_parameters: dict,
    ):
        ...

    def _before_eval_execution(
        self, env: Environment, resource_runtime_part: ResourceRuntimePart, raw_parameters: dict
    ) -> None:
        parameters_str = to_json_str(raw_parameters)

        scheduled_event_details = TaskScheduledEventDetails(
            resource=self._get_sfn_resource(),
            resourceType=self._get_sfn_resource_type(),
            region=resource_runtime_part.region,
            parameters=parameters_str,
        )
        if not self.timeout.is_default_value():
            self.timeout.eval(env=env)
            timeout_seconds = env.stack.pop()
            scheduled_event_details["timeoutInSeconds"] = timeout_seconds
        if self.heartbeat is not None:
            self.heartbeat.eval(env=env)
            heartbeat_seconds = env.stack.pop()
            scheduled_event_details["heartbeatInSeconds"] = heartbeat_seconds
        env.event_history.add_event(
            context=env.event_history_context,
            hist_type_event=HistoryEventType.TaskScheduled,
            event_detail=EventDetails(taskScheduledEventDetails=scheduled_event_details),
        )

        env.event_history.add_event(
            context=env.event_history_context,
            hist_type_event=HistoryEventType.TaskStarted,
            event_detail=EventDetails(
                taskStartedEventDetails=TaskStartedEventDetails(
                    resource=self._get_sfn_resource(), resourceType=self._get_sfn_resource_type()
                )
            ),
        )

    def _after_eval_execution(
        self,
        env: Environment,
        resource_runtime_part: ResourceRuntimePart,
        normalised_parameters: dict,
    ) -> None:
        output = env.stack[-1]
        env.event_history.add_event(
            context=env.event_history_context,
            hist_type_event=HistoryEventType.TaskSucceeded,
            event_detail=EventDetails(
                taskSucceededEventDetails=TaskSucceededEventDetails(
                    resource=self._get_sfn_resource(),
                    resourceType=self._get_sfn_resource_type(),
                    output=to_json_str(output),
                    outputDetails=HistoryEventExecutionDataDetails(truncated=False),
                )
            ),
        )

    def _eval_execution(self, env: Environment) -> None:
        self.resource.eval(env=env)
        resource_runtime_part: ResourceRuntimePart = env.stack.pop()

        raw_parameters = self._eval_parameters(env=env)

        self._before_eval_execution(
            env=env, resource_runtime_part=resource_runtime_part, raw_parameters=raw_parameters
        )

        normalised_parameters = copy.deepcopy(raw_parameters)
        self._normalise_parameters(normalised_parameters)

        self._eval_service_task(
            env=env,
            resource_runtime_part=resource_runtime_part,
            normalised_parameters=normalised_parameters,
        )

        output_value = env.stack[-1]
        self._normalise_response(output_value)

        self._after_eval_execution(
            env=env,
            resource_runtime_part=resource_runtime_part,
            normalised_parameters=normalised_parameters,
        )
