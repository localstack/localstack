from typing import Final

from localstack.services.stepfunctions.asl.component.state.state_wait.wait_function.wait_function import (
    WaitFunction,
)
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.services.stepfunctions.asl.utils.json_path import JSONPathUtils


class SecondsPath(WaitFunction):
    # SecondsPath
    # A time, in seconds, to state_wait before beginning the state specified in the Next
    # field, specified using a path from the state's input data.
    # You must specify an integer value for this field.

    def __init__(self, path: str):
        self.path: Final[str] = path

    def _get_wait_seconds(self, env: Environment) -> int:
        inp = env.stack[-1]
        seconds = JSONPathUtils.extract_json(self.path, inp)
        if not isinstance(seconds, int) and seconds <= 0:
            raise ValueError(
                f"Expected non-negative integer for SecondsPath, got '{type(seconds).__name__}' '{seconds}' instead."
            )
        return seconds
