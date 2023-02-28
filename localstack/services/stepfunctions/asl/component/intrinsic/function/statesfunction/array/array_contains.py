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


class ArrayContains(StatesFunction):
    # Determines if a specific value is present in an array.
    #
    # For example:
    # With input
    # {
    #    "inputArray": [1,2,3,4,5,6,7,8,9],
    #    "lookingFor": 5
    # }
    #
    # The call:
    # States.ArrayContains($.inputArray, $.lookingFor)
    #
    # Returns:
    # true
    def __init__(self, arg_list: FunctionArgumentList):
        super().__init__(
            states_name=StatesFunctionName(function_type=StatesFunctionNameType.ArrayContains),
            arg_list=arg_list,
        )
        if arg_list.size != 2:
            raise ValueError(
                f"Expected 2 arguments for function type '{type(self)}', but got: '{arg_list}'."
            )

    def _eval_body(self, env: Environment) -> None:
        self.arg_list.eval(env=env)
        value = env.stack.pop()
        array = env.stack.pop()
        if not isinstance(array, list):
            raise TypeError(f"Expected an array type as first argument, but got {array}.")
        contains = value in array
        env.stack.append(contains)
