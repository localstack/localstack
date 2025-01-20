import decimal
from typing import Any

from localstack.services.stepfunctions.asl.component.intrinsic.argument.argument import (
    ArgumentList,
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


def _round_like_java(f: float) -> int:
    # this behaves a bit weird for boundary values
    # AWS stepfunctions is implemented in Java, so we need to adjust the rounding accordingly
    # python by default rounds half to even
    if f >= 0:
        decimal.getcontext().rounding = decimal.ROUND_HALF_UP
    else:
        decimal.getcontext().rounding = decimal.ROUND_HALF_DOWN
    d = decimal.Decimal(f)
    return round(d, 0)


class MathAdd(StatesFunction):
    # Returns the sum of two numbers.
    #
    # For example:
    # With input
    # {
    #    "value1": 111,
    #    "step": -1
    # }
    #
    # Call
    # "value1.$": "States.MathAdd($.value1, $.step)"
    #
    # Returns
    # {"value1": 110 }

    def __init__(self, argument_list: ArgumentList):
        super().__init__(
            states_name=StatesFunctionName(function_type=StatesFunctionNameType.MathAdd),
            argument_list=argument_list,
        )
        if argument_list.size != 2:
            raise ValueError(
                f"Expected 2 arguments for function type '{type(self)}', but got: '{argument_list}'."
            )

    @staticmethod
    def _validate_integer_value(value: Any) -> int:
        if not isinstance(value, (int, float)):
            raise TypeError(f"Expected integer value, but got: '{value}'.")
        # If you specify a non-integer value for one or both the arguments,
        # Step Functions will round it off to the nearest integer.

        if isinstance(value, float):
            result = _round_like_java(value)
            return int(result)

        return value

    def _eval_body(self, env: Environment) -> None:
        self.argument_list.eval(env=env)
        args = env.stack.pop()

        a = self._validate_integer_value(args[0])
        b = self._validate_integer_value(args[1])

        res = a + b
        env.stack.append(res)
