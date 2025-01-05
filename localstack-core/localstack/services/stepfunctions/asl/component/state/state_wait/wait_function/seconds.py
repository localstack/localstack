from typing import Final

from localstack.services.stepfunctions.asl.component.common.string.string_expression import (
    StringJSONata,
)
from localstack.services.stepfunctions.asl.component.state.state_wait.wait_function.wait_function import (
    WaitFunction,
)
from localstack.services.stepfunctions.asl.eval.environment import Environment


class Seconds(WaitFunction):
    # Seconds
    # A time, in seconds, to state_wait before beginning the state specified in the Next
    # field. You must specify time as a positive, integer value.

    def __init__(self, seconds: int):
        self.seconds: Final[int] = seconds

    def _get_wait_seconds(self, env: Environment) -> int:
        return self.seconds


class SecondsJSONata(WaitFunction):
    string_jsonata: Final[StringJSONata]

    def __init__(self, string_jsonata: StringJSONata):
        super().__init__()
        self.string_jsonata = string_jsonata

    def _get_wait_seconds(self, env: Environment) -> int:
        # TODO: add snapshot tests to verify AWS's behaviour about non integer values.
        self.string_jsonata.eval(env=env)
        max_items: int = int(env.stack.pop())
        return max_items
