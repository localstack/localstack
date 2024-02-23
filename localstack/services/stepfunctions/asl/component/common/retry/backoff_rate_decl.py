from typing import Final

from localstack.services.stepfunctions.asl.component.eval_component import EvalComponent
from localstack.services.stepfunctions.asl.eval.environment import Environment


class BackoffRateDecl(EvalComponent):
    """
    "BackoffRate": a number which is the multiplier that increases the retry interval on each
    attempt (default: 2.0). The value of BackoffRate MUST be greater than or equal to 1.0.
    """

    DEFAULT_RATE: Final[float] = 2.0
    MIN_RATE: Final[float] = 1.0

    def __init__(self, rate: float = DEFAULT_RATE):
        if not (rate >= self.MIN_RATE):
            raise ValueError(
                f"The value of BackoffRate MUST be greater than or equal to {BackoffRateDecl.MIN_RATE}, got '{rate}'."
            )
        self.rate: Final[float] = rate

    def _next_multiplier_key(self) -> str:
        return f"BackoffRateDecl-{self.heap_key}-next_multiplier"

    def _access_next_multiplier(self, env: Environment) -> float:
        return env.heap.get(self._next_multiplier_key(), 1.0)

    def _store_next_multiplier(self, env: Environment, next_multiplier: float) -> None:
        env.heap[self._next_multiplier_key()] = next_multiplier

    def _eval_body(self, env: Environment) -> None:
        interval_seconds: int = env.stack.pop()

        next_multiplier: float = self._access_next_multiplier(env=env)

        next_interval_seconds = interval_seconds * next_multiplier
        env.stack.append(next_interval_seconds)

        next_multiplier *= self.rate
        self._store_next_multiplier(env=env, next_multiplier=next_multiplier)
