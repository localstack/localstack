from typing import Final

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
