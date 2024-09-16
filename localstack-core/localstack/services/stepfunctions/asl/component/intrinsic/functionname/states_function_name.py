from localstack.services.stepfunctions.asl.component.intrinsic.functionname.function_name import (
    FunctionName,
)
from localstack.services.stepfunctions.asl.component.intrinsic.functionname.state_function_name_types import (
    StatesFunctionNameType,
)


class StatesFunctionName(FunctionName):
    def __init__(self, function_type: StatesFunctionNameType):
        super().__init__(name=function_type.name())
        self.function_type: StatesFunctionNameType = function_type
