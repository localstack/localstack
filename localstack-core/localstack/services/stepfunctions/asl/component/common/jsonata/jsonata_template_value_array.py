from typing import Final

from localstack.services.stepfunctions.asl.component.common.jsonata.jsonata_template_value import (
    JSONataTemplateValue,
)
from localstack.services.stepfunctions.asl.eval.environment import Environment


class JSONataTemplateValueArray(JSONataTemplateValue):
    values: Final[list[JSONataTemplateValue]]

    def __init__(self, values: list[JSONataTemplateValue]):
        self.values = values

    def _eval_body(self, env: Environment) -> None:
        arr = list()
        for value in self.values:
            value.eval(env)
            arr.append(env.stack.pop())
        env.stack.append(arr)
