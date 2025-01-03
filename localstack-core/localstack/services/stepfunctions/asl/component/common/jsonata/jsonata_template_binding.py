from __future__ import annotations

from typing import Final, Optional

from localstack.services.stepfunctions.asl.component.common.jsonata.jsonata_template_value import (
    JSONataTemplateValue,
)
from localstack.services.stepfunctions.asl.component.eval_component import EvalComponent
from localstack.services.stepfunctions.asl.eval.environment import Environment


class JSONataTemplateBinding(EvalComponent):
    identifier: Final[str]
    value: Final[JSONataTemplateValue]

    def __init__(self, identifier: str, value: JSONataTemplateValue):
        self.identifier = identifier
        self.value = value

    def _field_name(self) -> Optional[str]:
        return self.identifier

    def _eval_body(self, env: Environment) -> None:
        binding_container: dict = env.stack.pop()
        self.value.eval(env=env)
        value = env.stack.pop()
        binding_container[self.identifier] = value
        env.stack.append(binding_container)
