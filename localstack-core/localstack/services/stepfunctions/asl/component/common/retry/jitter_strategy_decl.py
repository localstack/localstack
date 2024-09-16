import enum
import random
from typing import Final

from localstack.services.stepfunctions.asl.antlr.runtime.ASLLexer import ASLLexer
from localstack.services.stepfunctions.asl.component.eval_component import EvalComponent
from localstack.services.stepfunctions.asl.eval.environment import Environment


class JitterStrategy(enum.Enum):
    FULL = ASLLexer.FULL
    NONE = ASLLexer.NONE

    def __str__(self):
        return self.name

    def __repr__(self):
        return f"JitterStrategy.{self}({self.value})"


class JitterStrategyDecl(EvalComponent):
    DEFAULT_STRATEGY: Final[JitterStrategy] = JitterStrategy.NONE

    jitter_strategy: Final[JitterStrategy]

    def __init__(self, jitter_strategy: JitterStrategy = JitterStrategy.NONE):
        self.jitter_strategy = jitter_strategy

    def _eval_body(self, env: Environment) -> None:
        if self.jitter_strategy == JitterStrategy.NONE:
            return

        interval_seconds = env.stack.pop()
        jitter_interval = random.uniform(0, interval_seconds)
        env.stack.append(jitter_interval)
