from __future__ import annotations

import abc
import datetime
import logging
from abc import ABC
from typing import Optional

from localstack.services.stepfunctions.asl.component.common.comment import Comment
from localstack.services.stepfunctions.asl.component.common.flow.end import End
from localstack.services.stepfunctions.asl.component.common.flow.next import Next
from localstack.services.stepfunctions.asl.component.common.path.input_path import InputPath
from localstack.services.stepfunctions.asl.component.common.path.output_path import OutputPath
from localstack.services.stepfunctions.asl.component.eval_component import EvalComponent
from localstack.services.stepfunctions.asl.component.state.state_continue_with import (
    ContinueWith,
    ContinueWithEnd,
    ContinueWithNext,
)
from localstack.services.stepfunctions.asl.component.state.state_props import StateProps
from localstack.services.stepfunctions.asl.component.state.state_type import StateType
from localstack.services.stepfunctions.asl.eval.contextobject.contex_object import State, Task
from localstack.services.stepfunctions.asl.eval.environment import Environment

LOG = logging.getLogger(__name__)


class CommonStateField(EvalComponent, ABC):
    name: str

    # The state's type.
    state_type: StateType

    # There can be any number of terminal states per state machine. Only one of Next or End can
    # be used in a state. Some state types, such as Choice, don't support or use the End field.
    continue_with: ContinueWith

    def __init__(self):
        # Holds a human-readable description of the state.
        self.comment: Optional[Comment] = None

        # A path that selects a portion of the state's input to be passed to the state's state_task for processing.
        # If omitted, it has the value $ which designates the entire input.
        self.input_path: InputPath = InputPath(InputPath.DEFAULT_PATH)

        # A path that selects a portion of the state's output to be passed to the next state.
        # If omitted, it has the value $ which designates the entire output.
        self.output_path: OutputPath = OutputPath(OutputPath.DEFAULT_PATH)

    def from_state_props(self, state_props: StateProps) -> None:
        self.name = state_props.name
        self.state_type = state_props.get(StateType)
        self.continue_with = (
            ContinueWithEnd() if state_props.get(End) else ContinueWithNext(state_props.get(Next))
        )
        self.comment = state_props.get(Comment)
        self.input_path = state_props.get(InputPath) or InputPath(InputPath.DEFAULT_PATH)
        self.output_path = state_props.get(OutputPath) or OutputPath(OutputPath.DEFAULT_PATH)

    def _set_next(self, env: Environment) -> None:
        if env.next_state_name != self.name:
            # Next was already overriden.
            return

        if isinstance(self.continue_with, ContinueWithNext):
            env.next_state_name = self.continue_with.next_state.name
        elif isinstance(self.continue_with, ContinueWithEnd):  # This includes ContinueWithSuccess
            env.set_ended()
        else:
            LOG.error(f"Could not handle ContinueWith type of '{type(self.continue_with)}'.")

    @abc.abstractmethod
    def _eval_state(self, env: Environment) -> None:
        ...

    def _eval_body(self, env: Environment) -> None:
        env.context_object["State"] = State(
            EnteredTime=datetime.datetime.now().isoformat(), Name=self.name, RetryCount=0
        )

        # Filter the input onto the stack.
        if self.input_path:
            self.input_path.eval(env)

        # Exec the state's logic.
        self._eval_state(env)

        # Filter the input onto the input.
        if self.output_path:
            self.output_path.eval(env)

        # Set next state or halt (end).
        self._set_next(env)
