from typing import Final, Optional

from localstack.services.stepfunctions.asl.component.common.string.string_expression import (
    StringSampler,
)
from localstack.services.stepfunctions.asl.component.eval_component import EvalComponent
from localstack.services.stepfunctions.asl.eval.environment import Environment


class OutputPath(EvalComponent):
    string_sampler: Final[Optional[StringSampler]]

    def __init__(self, string_sampler: Optional[StringSampler]):
        self.string_sampler = string_sampler

    def _eval_body(self, env: Environment) -> None:
        if self.string_sampler is None:
            env.states.reset(input_value=dict())
            return
        self.string_sampler.eval(env=env)
        output_value = env.stack.pop()
        env.states.reset(output_value)
