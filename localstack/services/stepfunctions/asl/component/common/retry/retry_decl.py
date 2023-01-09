from typing import Final

from localstack.services.stepfunctions.asl.component.common.error_name.error_name import ErrorName
from localstack.services.stepfunctions.asl.component.common.retry.retrier_decl import RetrierDecl
from localstack.services.stepfunctions.asl.component.common.retry.retrier_outcome import (
    RetrierOutcome,
)
from localstack.services.stepfunctions.asl.component.common.retry.retry_outcome import RetryOutcome
from localstack.services.stepfunctions.asl.component.eval_component import EvalComponent
from localstack.services.stepfunctions.asl.eval.environment import Environment


class RetryDecl(EvalComponent):
    def __init__(self, retriers: list[RetrierDecl]):
        self.retriers: Final[list[RetrierDecl]] = retriers

    def _eval_body(self, env: Environment) -> None:
        error_name: ErrorName = env.stack.pop()

        for retrier in self.retriers:
            env.stack.append(error_name)
            retrier.eval(env)
            outcome: RetrierOutcome = env.stack.pop()

            match outcome:
                case RetrierOutcome.Skipped:
                    continue
                case RetrierOutcome.Executed:
                    env.stack.append(RetryOutcome.CanRetry)
                    return
                case RetrierOutcome.Failed:
                    env.stack.append(RetryOutcome.CannotRetry)
                    return

        env.stack.append(RetryOutcome.NoRetrier)
