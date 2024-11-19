from __future__ import annotations

from typing import Final, Optional

from localstack.services.stepfunctions.asl.component.common.assign.assign_decl import AssignDecl
from localstack.services.stepfunctions.asl.component.common.catch.catcher_outcome import (
    CatcherOutcomeCaught,
    CatcherOutcomeNotCaught,
)
from localstack.services.stepfunctions.asl.component.common.catch.catcher_props import CatcherProps
from localstack.services.stepfunctions.asl.component.common.comment import Comment
from localstack.services.stepfunctions.asl.component.common.error_name.error_equals_decl import (
    ErrorEqualsDecl,
)
from localstack.services.stepfunctions.asl.component.common.error_name.failure_event import (
    FailureEvent,
)
from localstack.services.stepfunctions.asl.component.common.flow.next import Next
from localstack.services.stepfunctions.asl.component.common.outputdecl import Output
from localstack.services.stepfunctions.asl.component.common.path.result_path import ResultPath
from localstack.services.stepfunctions.asl.component.eval_component import EvalComponent
from localstack.services.stepfunctions.asl.eval.environment import Environment


class CatcherOutput(dict):
    def __init__(self, error: str, cause: str):
        super().__init__()
        self["Error"] = error
        self["Cause"] = cause


class CatcherDecl(EvalComponent):
    DEFAULT_RESULT_PATH: Final[ResultPath] = ResultPath(result_path_src="$")

    error_equals: Final[ErrorEqualsDecl]
    next_decl: Final[Next]
    result_path: Final[Optional[ResultPath]]
    assign: Final[Optional[AssignDecl]]
    output: Final[Optional[Output]]
    comment: Final[Optional[Comment]]

    def __init__(
        self,
        error_equals: ErrorEqualsDecl,
        next_decl: Next,
        result_path: Optional[ResultPath],
        assign: Optional[AssignDecl],
        output: Optional[Output],
        comment: Optional[Comment],
    ):
        self.error_equals = error_equals
        self.next_decl = next_decl
        self.result_path = result_path
        self.assign = assign
        self.output = output
        self.comment = comment

    @classmethod
    def from_catcher_props(cls, props: CatcherProps) -> CatcherDecl:
        return cls(
            error_equals=props.get(
                typ=ErrorEqualsDecl,
                raise_on_missing=ValueError(
                    f"Missing ErrorEquals declaration for Catcher declaration, in props '{props}'."
                ),
            ),
            next_decl=props.get(
                typ=Next,
                raise_on_missing=ValueError(
                    f"Missing Next declaration for Catcher declaration, in props '{props}'."
                ),
            ),
            result_path=props.get(typ=ResultPath),
            assign=props.get(typ=AssignDecl),
            output=props.get(typ=Output),
            comment=props.get(typ=Comment),
        )

    def _eval_body(self, env: Environment) -> None:
        failure_event: FailureEvent = env.stack.pop()

        env.stack.append(failure_event.error_name)
        self.error_equals.eval(env)

        equals: bool = env.stack.pop()
        if equals:
            # Input for the catch block is the error output.
            env.stack.append(env.states.get_error_output())

            if self.assign:
                self.assign.eval(env=env)

            if self.result_path:
                self.result_path.eval(env)

            # Prepare the state output: successful catch states override the states' output procedure.
            if self.output:
                self.output.eval(env=env)
            else:
                output_value = env.stack.pop()
                env.states.reset(output_value)

            # Append successful output to notify the outcome upstream.
            env.next_state_name = self.next_decl.name
            env.stack.append(CatcherOutcomeCaught())
        else:
            env.stack.append(failure_event)
            env.stack.append(CatcherOutcomeNotCaught())
