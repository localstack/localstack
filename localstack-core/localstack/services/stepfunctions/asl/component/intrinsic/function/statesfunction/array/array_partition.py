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


class ArrayPartition(StatesFunction):
    # Partitions the input array.
    #
    # For example:
    # With input
    # {
    #   "inputArray": [1, 2, 3, 4, 5, 6, 7, 8, 9]
    # }
    #
    # The call
    # States.ArrayPartition($.inputArray,4)
    #
    # Returns
    # [ [1,2,3,4], [5,6,7,8], [9]]

    def __init__(self, arg_list: FunctionArgumentList):
        super().__init__(
            states_name=StatesFunctionName(function_type=StatesFunctionNameType.ArrayPartition),
            arg_list=arg_list,
        )
        if arg_list.size != 2:
            raise ValueError(
                f"Expected 2 arguments for function type '{type(self)}', but got: '{arg_list}'."
            )

    def _eval_body(self, env: Environment) -> None:
        self.arg_list.eval(env=env)
        args = env.stack.pop()

        chunk_size = args.pop()
        if not isinstance(chunk_size, (int, float)):
            raise TypeError(f"Expected an integer value as chunk_size, but got {chunk_size}.")
        chunk_size = round(chunk_size)
        if chunk_size < 0:
            raise ValueError(
                f"Expected a non-zero, positive integer as chuck_size, but got {chunk_size}."
            )

        array = args.pop()
        if not isinstance(array, list):
            raise TypeError(f"Expected an array type as first argument, but got {array}.")

        chunks = self._to_chunks(array=array, chunk_size=chunk_size)
        env.stack.append(chunks)

    @staticmethod
    def _to_chunks(array: list, chunk_size: int):
        chunks = list()
        for i in range(0, len(array), chunk_size):
            chunks.append(array[i : i + chunk_size])
        return chunks
