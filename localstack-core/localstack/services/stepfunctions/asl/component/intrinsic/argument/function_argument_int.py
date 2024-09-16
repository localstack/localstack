from localstack.services.stepfunctions.asl.component.intrinsic.argument.function_argument import (
    FunctionArgument,
)


class FunctionArgumentInt(FunctionArgument):
    _value: int

    def __init__(self, integer: int):
        super().__init__(value=integer)
