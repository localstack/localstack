from __future__ import annotations

import time
from typing import Final, Optional

from localstack.services.stepfunctions.asl.component.common.comment import Comment
from localstack.services.stepfunctions.asl.component.common.error_name.error_equals_decl import (
    ErrorEqualsDecl,
)
from localstack.services.stepfunctions.asl.component.common.retry.backoff_rate_decl import (
    BackoffRateDecl,
)
from localstack.services.stepfunctions.asl.component.common.retry.interval_seconds_decl import (
    IntervalSecondsDecl,
)
from localstack.services.stepfunctions.asl.component.common.retry.max_attempts_decl import (
    MaxAttemptsDecl,
)
from localstack.services.stepfunctions.asl.component.common.retry.retrier_outcome import (
    RetrierOutcome,
)
from localstack.services.stepfunctions.asl.component.common.retry.retrier_props import RetrierProps
from localstack.services.stepfunctions.asl.component.eval_component import EvalComponent
from localstack.services.stepfunctions.asl.eval.environment import Environment


class RetrierDecl(EvalComponent):
    error_equals: Final[ErrorEqualsDecl]
    interval_seconds: Final[IntervalSecondsDecl]
    max_attempts: Final[MaxAttemptsDecl]
    backoff_rate: Final[BackoffRateDecl]
    comment: Final[Optional[Comment]]

    def __init__(
        self,
        error_equals: ErrorEqualsDecl,
        interval_seconds: Optional[IntervalSecondsDecl] = None,
        max_attempts: Optional[MaxAttemptsDecl] = None,
        backoff_rate: Optional[BackoffRateDecl] = None,
        comment: Optional[Comment] = None,
    ):
        self.error_equals = error_equals
        self.interval_seconds = interval_seconds or IntervalSecondsDecl()
        self.max_attempts = max_attempts or MaxAttemptsDecl()
        self.backoff_rate = backoff_rate or BackoffRateDecl()
        self.comment = comment

        self._attempts_counter: int = 0
        self._next_interval_seconds: float = self.interval_seconds.seconds

    @classmethod
    def from_retrier_props(cls, props: RetrierProps) -> RetrierDecl:
        return cls(
            error_equals=props.get(
                typ=ErrorEqualsDecl,
                raise_on_missing=ValueError(
                    f"Missing ErrorEquals declaration for Retrier declaration, in props '{props}'."
                ),
            ),
            interval_seconds=props.get(IntervalSecondsDecl),
            max_attempts=props.get(MaxAttemptsDecl),
            backoff_rate=props.get(BackoffRateDecl),
            comment=props.get(Comment),
        )

    def _eval_body(self, env: Environment) -> None:
        # When a state reports an error, the interpreter scans through the Retriers and, when the Error Name appears
        # in the value of a Retrier’s "ErrorEquals" field, implements the retry policy described in that Retrier.

        self.error_equals.eval(env)
        res: bool = env.stack.pop()

        # This Retrier does not match
        if not res:
            env.stack.append(RetrierOutcome.Skipped)
            return

        # This is a matching Retrier, but was exhausted.
        self._attempts_counter += 1
        if self._attempts_counter > self.max_attempts.attempts:
            env.stack.append(RetrierOutcome.Failed)
            return

        # Execute the Retrier logic.
        # TODO: continue after interrupts?
        time.sleep(self._next_interval_seconds)

        self._next_interval_seconds = (
            self._attempts_counter * self.interval_seconds.seconds * self.backoff_rate.rate
        )

        env.stack.append(RetrierOutcome.Executed)
