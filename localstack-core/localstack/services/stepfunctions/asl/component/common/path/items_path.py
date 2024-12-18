from typing import Final

from localstack.services.stepfunctions.asl.component.common.string.string_expression import (
    StringSampler,
)
from localstack.services.stepfunctions.asl.component.eval_component import EvalComponent
from localstack.services.stepfunctions.asl.eval.environment import Environment


class ItemsPath(EvalComponent):
    string_sampler: Final[StringSampler]

    def __init__(self, string_sampler: StringSampler):
        self.string_sampler = string_sampler

    def _eval_body(self, env: Environment) -> None:
        self.string_sampler.eval(env=env)
