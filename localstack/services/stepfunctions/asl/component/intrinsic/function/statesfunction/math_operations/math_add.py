from typing import Any

from localstack.services.stepfunctions.asl.component.intrinsic.argument.function_argument_list import (
    FunctionArgumentList,
)
from localstack.services.stepfunctions.asl.component.intrinsic.function.statesfunction.states_function import (
    StatesFunction,
)
from localstack.services.stepfunctions.asl.component.intrinsic.functionname.state_fuinction_name_types import (
    StatesFunctionNameType,
)
from localstack.services.stepfunctions.asl.component.intrinsic.functionname.states_function_name import (
    StatesFunctionName,
)
from localstack.services.stepfunctions.asl.eval.environment import Environment


class MathAdd(StatesFunction):
    def __init__(self, arg_list: FunctionArgumentList):
        super().__init__(
            states_name=StatesFunctionName(function_type=StatesFunctionNameType.MathAdd),
            arg_list=arg_list,
        )
        if arg_list.size != 2:
            raise ValueError(
                f"Expected 2 arguments for function type '{type(self)}', but got: '{arg_list}'."
            )

    @staticmethod
    def _validate_integer_value(value: Any) -> int:
        if not isinstance(value, (int, float)):
            raise ValueError(f"Expected integer value, but got: '{value}'.")
        return int(value)

    def _eval_body(self, env: Environment) -> None:
        self.arg_list.eval(env=env)

        b = self._validate_integer_value(env.stack.pop())
        a = self._validate_integer_value(env.stack.pop())

        res = a + b
        env.stack.append(res)
