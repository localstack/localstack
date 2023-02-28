from localstack.services.stepfunctions.asl.component.intrinsic.argument.function_argument_list import (
    FunctionArgumentList,
)
from localstack.services.stepfunctions.asl.component.intrinsic.function.statesfunction.states_function import (
    StatesFunction,
)
from localstack.services.stepfunctions.asl.component.intrinsic.functionname.state_function_name_types import (
    StatesFunctionNameType,
)
from localstack.services.stepfunctions.asl.component.intrinsic.functionname.states_function_name import (
    StatesFunctionName,
)
from localstack.services.stepfunctions.asl.eval.environment import Environment


class ArrayRange(StatesFunction):
    # Creates a new array containing a specific range of elements.
    #
    # For example:
    # The call
    # States.ArrayRange(1, 9, 2)
    #
    # Returns
    # [1,3,5,7,9]
    def __init__(self, arg_list: FunctionArgumentList):
        super().__init__(
            states_name=StatesFunctionName(function_type=StatesFunctionNameType.ArrayRange),
            arg_list=arg_list,
        )
        if arg_list.size != 3:
            raise ValueError(
                f"Expected 3 arguments for function type '{type(self)}', but got: '{arg_list}'."
            )

    def _eval_body(self, env: Environment) -> None:
        self.arg_list.eval(env=env)
        range_vals = [env.stack.pop(), env.stack.pop(), env.stack.pop()]
        for range_val in range_vals:
            if not isinstance(range_val, (int, float)):
                raise TypeError(
                    f"Expected 3 integer arguments for function type '{type(self)}', but got: '{range_vals}'."
                )
        step = round(range_vals[0])
        last = round(range_vals[1])
        first = round(range_vals[2])

        if step <= 0:
            raise ValueError(f"Expected step argument to be non negative, but got: '{step}'.")

        array = list(range(first, last + 1, step))

        if len(array) > 1000:
            raise ValueError(f"Arrays cannot contain more than 1000 items, size: {len(array)}.")

        env.stack.append(array)
