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


class ArrayLength(StatesFunction):
    # Returns the length of the array.
    #
    # For example:
    # With input
    # {
    #    "inputArray": [1,2,3,4,5,6,7,8,9]
    # }
    #
    # The call
    # States.ArrayLength($.inputArray)
    #
    # Returns
    # 9
    def __init__(self, argument_list: ArgumentList):
        super().__init__(
            states_name=StatesFunctionName(function_type=StatesFunctionNameType.ArrayLength),
            argument_list=argument_list,
        )
        if argument_list.size != 1:
            raise ValueError(
                f"Expected 1 argument for function type '{type(self)}', but got: '{argument_list}'."
            )

    def _eval_body(self, env: Environment) -> None:
        self.argument_list.eval(env=env)
        args = env.stack.pop()

        array = args.pop()
        if not isinstance(array, list):
            raise TypeError(f"Expected an array type, but got '{array}'.")

        length = len(array)
        env.stack.append(length)
