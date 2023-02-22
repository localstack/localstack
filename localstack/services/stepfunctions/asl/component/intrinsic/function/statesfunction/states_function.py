from localstack.services.stepfunctions.asl.component.intrinsic.argument.function_argument_list import (
    FunctionArgumentList,
)
from localstack.services.stepfunctions.asl.component.intrinsic.function.function import Function
from localstack.services.stepfunctions.asl.component.intrinsic.functionname.states_function_name import (
    StatesFunctionName,
)


class StatesFunction(Function):
    name: StatesFunctionName

    def __init__(self, states_name: StatesFunctionName, arg_list: FunctionArgumentList):
        super().__init__(name=states_name, arg_list=arg_list)
