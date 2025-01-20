from typing import Any, Final

from localstack.services.stepfunctions.asl.component.intrinsic.argument.argument import (
    ArgumentList,
    ArgumentLiteral,
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


class StatesFunctionFormat(StatesFunction):
    _DELIMITER: Final[str] = "{}"

    def __init__(self, argument_list: ArgumentList):
        super().__init__(
            states_name=StatesFunctionName(function_type=StatesFunctionNameType.Format),
            argument_list=argument_list,
        )
        if argument_list.size == 0:
            raise ValueError(
                f"Expected at least 1 argument for function type '{type(self)}', but got: '{argument_list}'."
            )
        first_argument = argument_list.arguments[0]
        if not (
            isinstance(first_argument, ArgumentLiteral)
            and isinstance(first_argument.definition_value, str)
        ):
            raise ValueError(
                f"Expected the first argument for function type '{type(self)}' to be a string, but got: '{first_argument}'."
            )

    def _eval_body(self, env: Environment) -> None:
        # TODO: investigate behaviour for incorrect number of arguments in string format.
        self.argument_list.eval(env=env)

        values: list[Any] = list()
        for _ in range(self.argument_list.size):
            values.append(env.stack.pop())
        string_format: str = values.pop()
        values.reverse()

        string_format_parts: list[str] = string_format.split(self._DELIMITER)
        string_result: str = ""
        for part in string_format_parts:
            string_result += part
            string_result += values.pop()

        env.stack.append(string_result)
