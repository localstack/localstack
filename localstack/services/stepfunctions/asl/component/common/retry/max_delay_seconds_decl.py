from typing import Final

from localstack.services.stepfunctions.asl.component.eval_component import EvalComponent
from localstack.services.stepfunctions.asl.eval.environment import Environment


class MaxDelaySecondsDecl(EvalComponent):
    MAX_VALUE: Final[int] = 31622401

    max_delays_seconds: Final[int]

    def __init__(self, max_delays_seconds: int = MAX_VALUE):
        if not (1 <= max_delays_seconds <= MaxDelaySecondsDecl.MAX_VALUE):
            raise ValueError(
                f"MaxDelaySeconds value MUST be a positive integer between "
                f"1 and {MaxDelaySecondsDecl.MAX_VALUE}, got '{max_delays_seconds}'."
            )

        self.max_delays_seconds = max_delays_seconds

    def _eval_body(self, env: Environment) -> None:
        interval_seconds = env.stack.pop()
        new_interval_seconds = min(interval_seconds, self.max_delays_seconds)
        env.stack.append(new_interval_seconds)
