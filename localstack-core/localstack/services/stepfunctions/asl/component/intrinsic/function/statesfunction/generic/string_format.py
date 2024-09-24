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
from localstack.services.stepfunctions.asl.component.intrinsic.functionname.state_function_name_types import (
    StatesFunctionNameType,
)
from localstack.services.stepfunctions.asl.component.intrinsic.functionname.states_function_name import (
    StatesFunctionName,
)
from localstack.services.stepfunctions.asl.eval.environment import Environment


class StringFormat(StatesFunction):
    # It constructs a string from both literal and interpolated values. This function takes one or more arguments.
    # The value of the first argument must be a string, and may include zero or more instances of the character
    # sequence {}. The interpreter returns the string defined in the first argument with each {} replaced by the value
    # of the positionally-corresponding argument in the Intrinsic invocation.
    #
    # For example:
    # With input
    # {
    #  "name": "Arnav",
    #  "template": "Hello, my name is {}."
    # }
    #
    # Calls
    # States.Format('Hello, my name is {}.', $.name)
    # States.Format($.template, $.name)
    #
    # Return
    # Hello, my name is Arnav.
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
        args = env.stack.pop()

        string_format: str = args[0]
        values: list[Any] = args[1:]

        values_str_repr = map(self._to_str_repr, values)
        string_result = string_format.format(*values_str_repr)

        env.stack.append(string_result)

    @staticmethod
    def _to_str_repr(value: Any) -> str:
        # Converts a value or object to a string representation compatible with sfn.
        # For example:
        # Input object
        # {
        #   "Arg1": 1,
        #   "Arg2": []
        # }
        # Is mapped to the string
        # {Arg1=1, Arg2=[]}

        if isinstance(value, str):
            return value
        elif isinstance(value, list):
            value_parts: list[str] = list(map(StringFormat._to_str_repr, value))
            return f"[{', '.join(value_parts)}]"
        elif isinstance(value, dict):
            dict_items = list()
            for d_key, d_value in value.items():
                d_value_lit = StringFormat._to_str_repr(d_value)
                dict_items.append(f"{d_key}={d_value_lit}")
            return f"{{{', '.join(dict_items)}}}"
        else:
            # Return json representation of terminal value.
            return json.dumps(value)
