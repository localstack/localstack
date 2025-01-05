from typing import Final

from localstack.services.stepfunctions.asl.component.common.string.string_expression import (
    StringVariableSample,
)
from localstack.services.stepfunctions.asl.component.intrinsic.argument.function_argument import (
    FunctionArgument,
)
from localstack.services.stepfunctions.asl.eval.environment import Environment


class FunctionArgumentVar(FunctionArgument):
    string_variable_sample: Final[StringVariableSample]

    def __init__(self, string_variable_sample: StringVariableSample):
        super().__init__()
        self.string_variable_sample = string_variable_sample

    def _eval_body(self, env: Environment) -> None:
        self.string_variable_sample.eval(env=env)
        self._value = env.stack.pop()
        super()._eval_body(env=env)
