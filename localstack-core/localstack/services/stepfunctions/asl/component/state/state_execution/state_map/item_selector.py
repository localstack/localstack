from typing import Final

from localstack.services.stepfunctions.asl.component.common.assign.assign_template_value_object import (
    AssignTemplateValueObject,
)
from localstack.services.stepfunctions.asl.component.eval_component import EvalComponent
from localstack.services.stepfunctions.asl.eval.environment import Environment


class ItemSelector(EvalComponent):
    template_value_object: Final[AssignTemplateValueObject]

    def __init__(self, template_value_object: AssignTemplateValueObject):
        self.template_value_object = template_value_object

    def _eval_body(self, env: Environment) -> None:
        self.template_value_object.eval(env=env)
