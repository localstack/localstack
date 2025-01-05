from typing import Final

from localstack.services.stepfunctions.asl.component.common.assign.assign_template_binding import (
    AssignTemplateBinding,
)
from localstack.services.stepfunctions.asl.component.eval_component import EvalComponent
from localstack.services.stepfunctions.asl.eval.environment import Environment


class AssignDeclBinding(EvalComponent):
    binding: Final[AssignTemplateBinding]

    def __init__(self, binding: AssignTemplateBinding):
        super().__init__()
        self.binding = binding

    def _eval_body(self, env: Environment) -> None:
        env.stack.append(dict())
        self.binding.eval(env=env)
