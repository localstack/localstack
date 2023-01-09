import datetime
from typing import Final

from jsonpath_ng import parse

from localstack.services.stepfunctions.asl.component.state.state_wait.wait_function.timestamp import (
    Timestamp,
)
from localstack.services.stepfunctions.asl.component.state.state_wait.wait_function.wait_function import (
    WaitFunction,
)
from localstack.services.stepfunctions.asl.eval.environment import Environment


class TimestampPath(WaitFunction):
    # TimestampPath
    # An absolute time to state_wait until beginning the state specified in the Next field,
    # specified using a path from the state's input data.

    def __init__(self, path: str):
        self.path: Final[str] = path

    def _eval_body(self, env: Environment) -> None:
        input_expr = parse(self.path)
        timestamp_str = input_expr.find(env.inp)

        timestamp = datetime.datetime.strptime(timestamp_str, Timestamp.TIMESTAMP_FORMAT)
        timestamp_func = Timestamp(timestamp=timestamp)
        timestamp_func.eval(env)
