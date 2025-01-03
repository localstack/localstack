from localstack.services.stepfunctions.asl.component.intrinsic.argument.argument import (
    ArgumentList,
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
    def __init__(self, argument_list: ArgumentList):
        super().__init__(
            states_name=StatesFunctionName(function_type=StatesFunctionNameType.ArrayContains),
            argument_list=argument_list,
        )
        if argument_list.size != 2:
            raise ValueError(
                f"Expected 2 arguments for function type '{type(self)}', but got: '{argument_list}'."
            )

    def _eval_body(self, env: Environment) -> None:
        self.argument_list.eval(env=env)
        args = env.stack.pop()

        array = args[0]
        value = args[1]
        if not isinstance(array, list):
            raise TypeError(f"Expected an array type as first argument, but got {array}.")
        contains = value in array
        env.stack.append(contains)
