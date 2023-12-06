from localstack.services.stepfunctions.asl.component.intrinsic.argument.function_argument import (
    FunctionArgument,
)


class FunctionArgumentString(FunctionArgument):
    _value: str

    def __init__(self, string: str):
        super().__init__(value=string)
