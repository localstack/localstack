from typing import Any

from localstack.services.stepfunctions.asl.component.intrinsic.argument.argument import (
    ArgumentList,
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


class StatesFunctionArray(StatesFunction):
    def __init__(self, argument_list: ArgumentList):
        super().__init__(
            states_name=StatesFunctionName(function_type=StatesFunctionNameType.Array),
            argument_list=argument_list,
        )

    def _eval_body(self, env: Environment) -> None:
        self.argument_list.eval(env=env)
        values: list[Any] = list()
        for _ in range(self.argument_list.size):
            values.append(env.stack.pop())
        values.reverse()
        env.stack.append(values)
