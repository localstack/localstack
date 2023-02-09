import json
from typing import Any, Final

from localstack.services.stepfunctions.asl.component.intrinsic.argument.function_argument_list import (
    FunctionArgumentList,
)
from localstack.services.stepfunctions.asl.component.intrinsic.argument.function_argument_string import (
    FunctionArgumentString,
)
from localstack.services.stepfunctions.asl.component.intrinsic.function.statesfunction.states_function import (
    StatesFunction,
)
from localstack.services.stepfunctions.asl.component.intrinsic.functionname.state_fuinction_name_types import (
    StatesFunctionNameType,
)
from localstack.services.stepfunctions.asl.component.intrinsic.functionname.states_function_name import (
    StatesFunctionName,
)
from localstack.services.stepfunctions.asl.eval.environment import Environment


class StringFormat(StatesFunction):
    _DELIMITER: Final[str] = "{}"

    def __init__(self, arg_list: FunctionArgumentList):
        super().__init__(
            states_name=StatesFunctionName(function_type=StatesFunctionNameType.Format),
            arg_list=arg_list,
        )
        if arg_list.size == 0:
            raise ValueError(
                f"Expected at least 1 argument for function type '{type(self)}', but got: '{arg_list}'."
            )
        if not isinstance(arg_list.arg_list[0], FunctionArgumentString):
            raise ValueError(
                f"Expected the first argument for function type '{type(self)}' to be a string, but got: '{arg_list.arg_list[0]}'."
            )

    def _eval_body(self, env: Environment) -> None:
        # TODO: investigate behaviour for incorrect number of arguments in string format.
        self.arg_list.eval(env=env)

        values: list[Any] = list()
        for _ in range(self.arg_list.size):
            values.append(env.stack.pop())
        string_format: str = values.pop()
        values.reverse()

        string_format_parts: list[str] = string_format.split(self._DELIMITER)
        string_result: str = ""
        for part in string_format_parts:
            string_result += part
            if values:
                value = values.pop()
                if not isinstance(value, str):
                    value = self._json_to_literal(value)
                string_result += value

        env.stack.append(string_result)

    @staticmethod
    def _json_to_literal(value: Any) -> str:
        if isinstance(value, dict):
            dict_items = list()
            for d_key, d_value in value.items():
                d_value_lit = StringFormat._json_to_literal(d_value)
                dict_items.append(f"{d_key}={d_value_lit}")
            return f"{{{', '.join(dict_items)}}}"
        elif isinstance(value, list):
            return f"[{', '.join(list(map(StringFormat._json_to_literal, value)))}]"
        else:
            return json.dumps(value)
