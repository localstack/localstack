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
from localstack.services.stepfunctions.asl.component.common.retry.jitter_strategy_decl import (
    JitterStrategyDecl,
)
from localstack.services.stepfunctions.asl.component.common.retry.max_attempts_decl import (
    MaxAttemptsDecl,
    MaxAttemptsOutcome,
)
from localstack.services.stepfunctions.asl.component.common.retry.max_delay_seconds_decl import (
    MaxDelaySecondsDecl,
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
    max_delay_seconds: Final[MaxDelaySecondsDecl]
    jitter_strategy: Final[JitterStrategyDecl]
    comment: Final[Optional[Comment]]

    def __init__(
        self,
        error_equals: ErrorEqualsDecl,
        interval_seconds: Optional[IntervalSecondsDecl] = None,
        max_attempts: Optional[MaxAttemptsDecl] = None,
        backoff_rate: Optional[BackoffRateDecl] = None,
        max_delay_seconds: Optional[MaxDelaySecondsDecl] = None,
        jitter_strategy: Optional[JitterStrategyDecl] = None,
        comment: Optional[Comment] = None,
    ):
        self.error_equals = error_equals
        self.interval_seconds = interval_seconds or IntervalSecondsDecl()
        self.max_attempts = max_attempts or MaxAttemptsDecl()
        self.backoff_rate = backoff_rate or BackoffRateDecl()
        self.max_delay_seconds = max_delay_seconds or MaxDelaySecondsDecl()
        self.jitter_strategy = jitter_strategy or JitterStrategyDecl()
        self.comment = comment

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
            max_delay_seconds=props.get(MaxDelaySecondsDecl),
            jitter_strategy=props.get(JitterStrategyDecl),
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

        # Request another attempt.
        self.max_attempts.eval(env=env)
        max_attempts_outcome = env.stack.pop()
        if max_attempts_outcome == MaxAttemptsOutcome.EXHAUSTED:
            env.stack.append(RetrierOutcome.Failed)
            return

        # Compute the next interval.
        self.interval_seconds.eval(env=env)
        self.backoff_rate.eval(env=env)
        self.max_delay_seconds.eval(env=env)
        self.jitter_strategy.eval(env=env)

        # Execute wait.
        interval_seconds: float = env.stack.pop()
        time.sleep(interval_seconds)

        env.stack.append(RetrierOutcome.Executed)
