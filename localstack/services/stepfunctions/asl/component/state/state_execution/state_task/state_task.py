from __future__ import annotations

import abc
from typing import Optional

from localstack.aws.api.stepfunctions import HistoryEventType
from localstack.services.stepfunctions.asl.component.common.parameters import Parameters
from localstack.services.stepfunctions.asl.component.state.state_execution.execute_state import (
    ExecutionState,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.resource import (
    Resource,
)
from localstack.services.stepfunctions.asl.component.state.state_props import StateProps
from localstack.services.stepfunctions.asl.eval.contextobject.contex_object import Task
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

        # TimeoutSeconds (Optional)
        # If the state_task runs longer than the specified seconds, this state fails with a States.Timeout error name.
        # Must be a positive, non-zero integer. If not provided, the default value is 99999999. The count begins after
        # the state_task has been started, for example, when ActivityStarted or LambdaFunctionStarted are logged in the
        # Execution event history.

        # TimeoutSecondsPath (Optional)
        # If you want to provide a timeout value dynamically from the state input using a reference path, use
        # TimeoutSecondsPath. When resolved, the reference path must select fields whose values are positive integers.

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

    def _eval_body(self, env: Environment) -> None:
        env.context_object["Task"] = Task(Token="TODO")
        super(StateTask, self)._eval_body(env=env)
        env.context_object["Task"] = None
