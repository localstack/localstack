from typing import Final

from localstack.services.stepfunctions.asl.component.eval_component import EvalComponent
from localstack.services.stepfunctions.asl.component.intrinsic.argument.function_argument import (
    FunctionArgument,
)
from localstack.services.stepfunctions.asl.eval.environment import Environment


class FunctionArgumentList(EvalComponent):
    def __init__(self, arg_list: list[FunctionArgument]):
        self.arg_list: Final[list[FunctionArgument]] = arg_list
        self.size: Final[int] = len(arg_list)

    def _eval_body(self, env: Environment) -> None:
        values = list()
        for arg in self.arg_list:
            arg.eval(env=env)
            values.append(env.stack.pop())
        env.stack.append(values)
