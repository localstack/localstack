import abc
from typing import Any, Final

from localstack.services.stepfunctions.asl.component.common.assign.assign_template_value import (
    AssignTemplateValue,
)
from localstack.services.stepfunctions.asl.component.common.string.string_expression import (
    StringJSONata,
)
from localstack.services.stepfunctions.asl.eval.environment import Environment


class AssignTemplateValueTerminal(AssignTemplateValue, abc.ABC): ...


class AssignTemplateValueTerminalLit(AssignTemplateValueTerminal):
    value: Final[Any]

    def __init__(self, value: Any):
        super().__init__()
        self.value = value

    def _eval_body(self, env: Environment) -> None:
        env.stack.append(self.value)


class AssignTemplateValueTerminalStringJSONata(AssignTemplateValueTerminal):
    string_jsonata: Final[StringJSONata]

    def __init__(self, string_jsonata: StringJSONata):
        super().__init__()
        self.string_jsonata = string_jsonata

    def _eval_body(self, env: Environment) -> None:
        self.string_jsonata.eval(env=env)
