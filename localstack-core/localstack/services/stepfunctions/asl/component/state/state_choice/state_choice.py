from typing import Optional

from localstack.aws.api.stepfunctions import HistoryEventType
from localstack.services.stepfunctions.asl.component.common.flow.end import End
from localstack.services.stepfunctions.asl.component.common.flow.next import Next
from localstack.services.stepfunctions.asl.component.state.state import CommonStateField
from localstack.services.stepfunctions.asl.component.state.state_choice.choices_decl import (
    ChoicesDecl,
)
from localstack.services.stepfunctions.asl.component.state.state_choice.default_decl import (
    DefaultDecl,
)
from localstack.services.stepfunctions.asl.component.state.state_props import StateProps
from localstack.services.stepfunctions.asl.eval.environment import Environment


class StateChoice(CommonStateField):
    choices_decl: ChoicesDecl
    default_state: Optional[DefaultDecl]

    def __init__(self):
        super(StateChoice, self).__init__(
            state_entered_event_type=HistoryEventType.ChoiceStateEntered,
            state_exited_event_type=HistoryEventType.ChoiceStateExited,
        )
        self.default_state = None
        self._next_state_name = None

    def from_state_props(self, state_props: StateProps) -> None:
        super(StateChoice, self).from_state_props(state_props)
        self.choices_decl = state_props.get(ChoicesDecl)
        self.default_state = state_props.get(DefaultDecl)

        if state_props.get(Next) or state_props.get(End):
            raise ValueError(
                "Choice states don't support the End field. "
                "In addition, they use Next only inside their Choices field. "
                f"With state '{self}'."
            )

    def _set_next(self, env: Environment) -> None:
        pass

    def _eval_state(self, env: Environment) -> None:
        for rule in self.choices_decl.rules:
            rule.eval(env)
            res = env.stack.pop()
            if res is True:
                if not rule.next_stmt:
                    raise RuntimeError(
                        f"Missing Next definition for state_choice rule '{rule}' in choices '{self}'."
                    )
                env.stack.append(rule.next_stmt.name)
                return

        if self.default_state is None:
            raise RuntimeError("No branching option reached in state %s", self.name)
        env.stack.append(self.default_state.state_name)

    def _eval_state_output(self, env: Environment) -> None:
        next_state_name: str = env.stack.pop()

        # No choice rule matched: the default state is evaluated.
        if self.default_state and self.default_state.state_name == next_state_name:
            if self.assign_decl:
                self.assign_decl.eval(env=env)
            if self.output:
                self.output.eval(env=env)

        # Handle legacy output sequences if in JsonPath mode.
        if self._is_language_query_jsonpath():
            if self.output_path:
                self.output_path.eval(env=env)
            else:
                current_output = env.stack.pop()
                env.states.reset(input_value=current_output)

        env.next_state_name = next_state_name
