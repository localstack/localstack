from localstack.services.stepfunctions.asl.component.intrinsic.argument.function_argument import (
    FunctionArgument,
)


class FunctionArgumentFloat(FunctionArgument):
    _value: float

    def __init__(self, number: float):
        super().__init__(value=number)
