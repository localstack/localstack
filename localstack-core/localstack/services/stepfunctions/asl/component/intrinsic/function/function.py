import abc
from typing import Final

from localstack.services.stepfunctions.asl.component.eval_component import EvalComponent
from localstack.services.stepfunctions.asl.component.intrinsic.argument.argument import ArgumentList
from localstack.services.stepfunctions.asl.component.intrinsic.functionname.function_name import (
    FunctionName,
)


class Function(EvalComponent, abc.ABC):
    name: FunctionName
    argument_list: Final[ArgumentList]

    def __init__(self, name: FunctionName, argument_list: ArgumentList):
        self.name = name
        self.argument_list = argument_list
