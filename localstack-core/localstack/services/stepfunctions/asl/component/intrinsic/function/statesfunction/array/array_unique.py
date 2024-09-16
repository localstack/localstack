from collections import OrderedDict

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


class ArrayUnique(StatesFunction):
    # Removes duplicate values from an array and returns an array containing only unique elements
    #
    # For example:
    # With input
    # {
    #   "inputArray": [1,2,3,3,3,3,3,3,4]
    # }
    #
    # The call
    # States.ArrayUnique($.inputArray)
    #
    # Returns
    # [1,2,3,4]
    def __init__(self, arg_list: FunctionArgumentList):
        super().__init__(
            states_name=StatesFunctionName(function_type=StatesFunctionNameType.ArrayUnique),
            arg_list=arg_list,
        )
        if arg_list.size != 1:
            raise ValueError(
                f"Expected 1 argument for function type '{type(self)}', but got: '{arg_list}'."
            )

    def _eval_body(self, env: Environment) -> None:
        self.arg_list.eval(env=env)
        args = env.stack.pop()

        array = args.pop()
        if not isinstance(array, list):
            raise TypeError(f"Expected an array type, but got '{array}'.")

        # Remove duplicates through an ordered set, in this
        # case we consider they key set of an ordered dict.
        items_odict = OrderedDict.fromkeys(array).keys()
        unique_array = list(items_odict)
        env.stack.append(unique_array)
