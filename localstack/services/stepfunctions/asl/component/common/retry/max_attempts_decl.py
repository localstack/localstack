import enum
from typing import Final

from localstack.services.stepfunctions.asl.component.eval_component import EvalComponent
from localstack.services.stepfunctions.asl.eval.environment import Environment


class MaxAttemptsOutcome(enum.Enum):
    EXHAUSTED = False
    SUCCESS = True


class MaxAttemptsDecl(EvalComponent):
    """
    "MaxAttempts": value MUST be a non-negative integer, representing the maximum number
    of retry attempts (default: 3)
    """

    DEFAULT_ATTEMPTS: Final[int] = 3
    MAX_VALUE: Final[int] = 99999999

    attempts: Final[int]

    def __init__(self, attempts: int = DEFAULT_ATTEMPTS):
        if not (1 <= attempts <= MaxAttemptsDecl.MAX_VALUE):
            raise ValueError(
                f"MaxAttempts value MUST be a positive integer between "
                f"1 and {MaxAttemptsDecl.MAX_VALUE}, got '{attempts}'."
            )
        self.attempts = attempts

    def _attempt_number_key(self) -> str:
        return f"MaxAttemptsDecl-{self.heap_key}-attempt_number"

    def _access_attempt_number(self, env: Environment) -> int:
        return env.heap.get(self._attempt_number_key(), -1)

    def _store_attempt_number(self, env: Environment, attempt_number: float) -> None:
        env.heap[self._attempt_number_key()] = attempt_number

    def _eval_body(self, env: Environment) -> None:
        if self.attempts == 0:
            env.stack.append(MaxAttemptsOutcome.SUCCESS)
        else:
            attempt_number: int = self._access_attempt_number(env=env)
            attempt_number += 1
            env.stack.append(MaxAttemptsOutcome(attempt_number < self.attempts))
            self._store_attempt_number(env=env, attempt_number=attempt_number)
