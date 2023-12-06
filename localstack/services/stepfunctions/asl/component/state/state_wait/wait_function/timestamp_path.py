import datetime
from typing import Final

from localstack.services.stepfunctions.asl.component.state.state_wait.wait_function.timestamp import (
    Timestamp,
)
from localstack.services.stepfunctions.asl.component.state.state_wait.wait_function.wait_function import (
    WaitFunction,
)
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.services.stepfunctions.asl.utils.json_path import JSONPathUtils


class TimestampPath(WaitFunction):
    # TimestampPath
    # An absolute time to state_wait until beginning the state specified in the Next field,
    # specified using a path from the state's input data.

    def __init__(self, path: str):
        self.path: Final[str] = path

    def _get_wait_seconds(self, env: Environment) -> int:
        inp = env.stack[-1]
        timestamp_str = JSONPathUtils.extract_json(self.path, inp)
        timestamp = datetime.datetime.strptime(timestamp_str, Timestamp.TIMESTAMP_FORMAT)
        delta = timestamp - datetime.datetime.today()
        delta_sec = int(delta.total_seconds())
        return delta_sec
