import abc
from typing import Final

from localstack.services.stepfunctions.asl.component.eval_component import EvalComponent
from localstack.services.stepfunctions.asl.component.intrinsic.argument.function_argument_list import (
    FunctionArgumentList,
)
from localstack.services.stepfunctions.asl.component.intrinsic.functionname.function_name import (
    FunctionName,
)


class Function(EvalComponent, abc.ABC):
    name: FunctionName

    def __init__(self, name: FunctionName, arg_list: FunctionArgumentList):
        self.name = name
        self.arg_list: Final[FunctionArgumentList] = arg_list
