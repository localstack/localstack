from typing import Final

from localstack.services.stepfunctions.asl.component.common.jsonata.jsonata_template_binding import (
    JSONataTemplateBinding,
)
from localstack.services.stepfunctions.asl.component.common.jsonata.jsonata_template_value import (
    JSONataTemplateValue,
)
from localstack.services.stepfunctions.asl.eval.environment import Environment


class JSONataTemplateValueObject(JSONataTemplateValue):
    bindings: Final[list[JSONataTemplateBinding]]

    def __init__(self, bindings: list[JSONataTemplateBinding]):
        self.bindings = bindings

    def _eval_body(self, env: Environment) -> None:
        env.stack.append(dict())
        for binding in self.bindings:
            binding.eval(env)
