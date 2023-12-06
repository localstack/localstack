from typing import Final

from localstack.services.stepfunctions.asl.component.intrinsic.argument.function_argument import (
    FunctionArgument,
)
from localstack.services.stepfunctions.asl.component.intrinsic.function.function import Function
from localstack.services.stepfunctions.asl.eval.environment import Environment


class FunctionArgumentFunction(FunctionArgument):
    def __init__(self, function: Function):
        super().__init__()
        self.function: Final[Function] = function

    def _eval_body(self, env: Environment) -> None:
        self.function.eval(env=env)
        self._value = env.stack.pop()
        super()._eval_body(env=env)
