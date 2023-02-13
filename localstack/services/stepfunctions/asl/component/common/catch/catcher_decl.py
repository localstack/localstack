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
from localstack.services.stepfunctions.asl.component.common.error_name.error_name import ErrorName
from localstack.services.stepfunctions.asl.component.common.flow.next import Next
from localstack.services.stepfunctions.asl.component.common.path.result_path import ResultPath
from localstack.services.stepfunctions.asl.component.eval_component import EvalComponent
from localstack.services.stepfunctions.asl.eval.environment import Environment


class CatcherDecl(EvalComponent):
    def __init__(
        self,
        error_equals: ErrorEqualsDecl,
        next_decl: Next,
        result_path: ResultPath = ResultPath(result_path_src="$"),
    ):
        self.error_equals: Final[ErrorEqualsDecl] = error_equals
        self.result_path: Final[ResultPath] = result_path
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

    def _eval_body(self, env: Environment) -> None:
        error_name: ErrorName = env.stack[-1]
        self.error_equals.eval(env)

        equals: bool = env.stack.pop()
        if equals:
            env.stack.append(error_name.error_name)
            self.result_path.eval(env)

            env.next_state_name = self.next_decl.name

            env.stack.append(CatcherOutcomeCaught())
        else:
            env.stack.append(CatcherOutcomeNotCaught())
