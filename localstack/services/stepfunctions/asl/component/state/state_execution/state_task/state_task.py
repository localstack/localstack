from __future__ import annotations

import abc
from typing import Optional

from localstack.aws.api.stepfunctions import HistoryEventType
from localstack.services.stepfunctions.asl.component.common.parameters import Parameters
from localstack.services.stepfunctions.asl.component.state.state_execution.execute_state import (
    ExecutionState,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.service.resource import (
    Resource,
)
from localstack.services.stepfunctions.asl.component.state.state_props import StateProps
from localstack.services.stepfunctions.asl.eval.environment import Environment


class StateTask(ExecutionState, abc.ABC):
    resource: Resource

    def __init__(self):
        super(StateTask, self).__init__(
            state_entered_event_type=HistoryEventType.TaskStateEntered,
            state_exited_event_type=HistoryEventType.TaskStateExited,
        )
        # Parameters (Optional)
        # Used to state_pass information to the API actions of connected resources. The parameters can use a mix of static
        # JSON and JsonPath.
        self.parameters: Optional[Parameters] = None

        # Credentials (Optional)
        # Specifies a target role the state machine's execution role must assume before invoking the specified Resource.
        # Alternatively, you can also specify a JSONPath value that resolves to an IAM role ARN at runtime based on the
        # execution input. If you specify a JSONPath value, you must prefix it with the $. notation.

        # A Task state cannot include both TimeoutSeconds and TimeoutSecondsPath
        # HeartbeatSeconds (Optional)
        # If more time than the specified seconds elapses between heartbeats from the state_task, this state fails with a
        # States.Timeout error name. Must be a positive, non-zero integer less than the number of seconds specified in
        # the TimeoutSeconds field. If not provided, the default value is 99999999. For Activities, the count begins
        # when GetActivityTask receives a token and ActivityStarted is logged in the Execution event history.

        # HeartbeatSecondsPath (Optional)
        # If you want to provide a heartbeat value dynamically from the state input using a reference path, use
        # HeartbeatSecondsPath. When resolved, the reference path must select fields whose values are positive integers.

    def from_state_props(self, state_props: StateProps) -> None:
        super(StateTask, self).from_state_props(state_props)
        self.parameters = state_props.get(Parameters)
        self.resource = state_props.get(Resource)

    def _get_supported_parameters(self) -> Optional[set[str]]:  # noqa
        return None

    def _get_parameters_normalising_bindings(self) -> dict[str, str]:  # noqa
        return dict()

    def _eval_parameters(self, env: Environment) -> dict:
        # Eval raw parameters.
        parameters = dict()
        if self.parameters:
            self.parameters.eval(env=env)
            parameters = env.stack.pop()

        # Handle supported parameters.
        supported_parameters = self._get_supported_parameters()
        if supported_parameters:
            unsupported_parameters: list[str] = [
                parameter
                for parameter in parameters.keys()
                if parameter not in supported_parameters
            ]
            for unsupported_parameter in unsupported_parameters:
                parameters.pop(unsupported_parameter, None)

        # Normalise bindings.
        parameter_normalisers = self._get_parameters_normalising_bindings()
        for parameter_key in list(parameters.keys()):
            norm_parameter_key = parameter_normalisers.get(parameter_key, None)
            if norm_parameter_key:
                tmp = parameters[parameter_key]
                del parameters[parameter_key]
                parameters[norm_parameter_key] = tmp

        return parameters

    def _eval_body(self, env: Environment) -> None:
        super(StateTask, self)._eval_body(env=env)
        env.context_object_manager.context_object["Task"] = None
