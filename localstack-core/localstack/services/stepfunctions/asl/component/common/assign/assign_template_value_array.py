from typing import Final

from localstack.services.stepfunctions.asl.component.common.assign.assign_template_value import (
    AssignTemplateValue,
)
from localstack.services.stepfunctions.asl.eval.environment import Environment


class AssignTemplateValueArray(AssignTemplateValue):
    values: Final[list[AssignTemplateValue]]

    def __init__(self, values: list[AssignTemplateValue]):
        self.values = values

    def _eval_body(self, env: Environment) -> None:
        arr = list()
        for value in self.values:
            value.eval(env)
            arr.append(env.stack.pop())
        env.stack.append(arr)
