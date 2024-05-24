from typing import Final

from localstack.services.stepfunctions.asl.component.eval_component import EvalComponent
from localstack.services.stepfunctions.asl.eval.environment import Environment


class IntervalSecondsDecl(EvalComponent):
    """
    IntervalSeconds: its value MUST be a positive integer, representing the number of seconds before the
    first retry attempt (default value: 1);
    """

    DEFAULT_SECONDS: Final[int] = 1
    MAX_VALUE: Final[int] = 99999999

    def __init__(self, seconds: int = DEFAULT_SECONDS):
        if not (1 <= seconds <= IntervalSecondsDecl.MAX_VALUE):
            raise ValueError(
                f"IntervalSeconds value MUST be a positive integer between "
                f"1 and {IntervalSecondsDecl.MAX_VALUE}, got '{seconds}'."
            )

        self.seconds: Final[int] = seconds

    def _eval_body(self, env: Environment) -> None:
        env.stack.append(self.seconds)
