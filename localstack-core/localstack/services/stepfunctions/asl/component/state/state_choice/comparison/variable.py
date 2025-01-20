from typing import Final

from localstack.services.stepfunctions.asl.component.common.string.string_expression import (
    StringSampler,
)
from localstack.services.stepfunctions.asl.component.eval_component import EvalComponent
from localstack.services.stepfunctions.asl.eval.environment import Environment


class NoSuchVariable:
    def __init__(self, path: str):
        self.path: Final[str] = path


class Variable(EvalComponent):
    string_sampler: Final[StringSampler]

    def __init__(self, string_sampler: StringSampler):
        self.string_sampler = string_sampler

    def _eval_body(self, env: Environment) -> None:
        try:
            self.string_sampler.eval(env=env)
            value = env.stack.pop()
        except Exception as ex:
            value = NoSuchVariable(f"{self.string_sampler.literal_value}, {ex}")
        env.stack.append(value)
