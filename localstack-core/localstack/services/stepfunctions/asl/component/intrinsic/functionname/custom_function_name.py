from localstack.services.stepfunctions.asl.component.intrinsic.functionname.function_name import (
    FunctionName,
)


class CustomFunctionName(FunctionName):
    def __init__(self, name: str):
        super().__init__(name=name)
