from __future__ import annotations

from typing import Final

from localstack.services.stepfunctions.asl.component.common.catch.catcher_outcome import (
    CatcherOutcomeCaught,
    CatcherOutcomeNotCaught,
)
from localstack.services.stepfunctions.asl.component.common.catch.catcher_props import CatcherProps
from localstack.services.stepfunctions.asl.component.common.error_name.error_equals_decl import (
    ErrorEqualsDecl,
)
from localstack.services.stepfunctions.asl.component.common.error_name.failure_event import (
    FailureEvent,
)
from localstack.services.stepfunctions.asl.component.common.flow.next import Next
from localstack.services.stepfunctions.asl.component.common.path.result_path import ResultPath
from localstack.services.stepfunctions.asl.component.eval_component import EvalComponent
from localstack.services.stepfunctions.asl.eval.environment import Environment


class CatcherDecl(EvalComponent):
    _DEFAULT_RESULT_PATH: Final[ResultPath] = ResultPath(result_path_src="$")

    def __init__(
        self,
        error_equals: ErrorEqualsDecl,
        next_decl: Next,
        result_path: ResultPath = _DEFAULT_RESULT_PATH,
    ):
        self.error_equals: Final[ErrorEqualsDecl] = error_equals
        self.result_path: Final[ResultPath] = result_path or CatcherDecl._DEFAULT_RESULT_PATH
        self.next_decl: Final[Next] = next_decl

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
        )

    @staticmethod
    def _extract_error_cause(failure_event: FailureEvent) -> dict:
        # TODO: consider formalising all EventDetails to ensure FailureEvent can always reach the state below.
        #  As per AWS's Api specification, all failure event carry one
        #  details field, with at least fields 'cause and 'error'
        specs_event_details = list(failure_event.event_details.values())
        if (
            len(specs_event_details) != 1
            and "error" in specs_event_details
            and "cause" in specs_event_details
        ):
            raise RuntimeError(
                f"Internal Error: invalid event details declaration in FailureEvent: '{failure_event}'."
            )
        spec_event_details: dict = list(failure_event.event_details.values())[0]
        error = spec_event_details["error"]
        cause = spec_event_details.get("cause") or ""
        # Stepfunctions renames these fields to capital in this scenario.
        return {
            "Error": error,
            "Cause": cause,
        }

    def _eval_body(self, env: Environment) -> None:
        failure_event: FailureEvent = env.stack.pop()

        env.stack.append(failure_event.error_name)
        self.error_equals.eval(env)

        equals: bool = env.stack.pop()
        if equals:
            error_cause: dict = self._extract_error_cause(failure_event)
            env.stack.append(error_cause)

            self.result_path.eval(env)
            env.next_state_name = self.next_decl.name
            env.stack.append(CatcherOutcomeCaught())
        else:
            env.stack.append(failure_event)
            env.stack.append(CatcherOutcomeNotCaught())
