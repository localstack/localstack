import base64
from typing import Final

from localstack.services.stepfunctions.asl.component.intrinsic.argument.argument import (
    ArgumentList,
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


class Base64Encode(StatesFunction):
    # Decodes data based on MIME Base64 encoding scheme.
    #
    # For example:
    # With input
    # {
    #   "base64": "RGF0YSB0byBlbmNvZGU="
    # }
    #
    # The call
    # "data.$": "States.Base64Decode($.base64)"
    #
    # Returns
    # {"data": "Decoded data"}

    MAX_INPUT_CHAR_LEN: Final[int] = 10_000

    def __init__(self, argument_list: ArgumentList):
        super().__init__(
            states_name=StatesFunctionName(function_type=StatesFunctionNameType.Base64Encode),
            argument_list=argument_list,
        )
        if argument_list.size != 1:
            raise ValueError(
                f"Expected 1 argument for function type '{type(self)}', but got: '{argument_list}'."
            )

    def _eval_body(self, env: Environment) -> None:
        self.argument_list.eval(env=env)
        args = env.stack.pop()

        string: str = args.pop()
        if len(string) > self.MAX_INPUT_CHAR_LEN:
            raise ValueError(
                f"Maximum input string for function type '{type(self)}' "
                f"is '{self.MAX_INPUT_CHAR_LEN}', but got '{len(string)}'."
            )

        string_bytes = string.encode("ascii")
        string_base64_bytes = base64.b64encode(string_bytes)
        base64_string = string_base64_bytes.decode("ascii")
        env.stack.append(base64_string)
