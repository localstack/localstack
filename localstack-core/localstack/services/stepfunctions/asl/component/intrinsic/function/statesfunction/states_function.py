import abc

from localstack.services.stepfunctions.asl.component.intrinsic.argument.argument import (
    ArgumentList,
)
from localstack.services.stepfunctions.asl.component.intrinsic.function.function import Function
from localstack.services.stepfunctions.asl.component.intrinsic.functionname.states_function_name import (
    StatesFunctionName,
)


class StatesFunction(Function, abc.ABC):
    name: StatesFunctionName

    def __init__(self, states_name: StatesFunctionName, argument_list: ArgumentList):
        super().__init__(name=states_name, argument_list=argument_list)
