import abc
from typing import Final

from localstack.services.stepfunctions.asl.component.common.jsonata.jsonata_template_value_object import (
    JSONataTemplateValueObject,
)
from localstack.services.stepfunctions.asl.component.common.payload.payloadvalue.payloadtmpl.payload_tmpl import (
    PayloadTmpl,
)
from localstack.services.stepfunctions.asl.component.common.string.string_expression import (
    StringJSONata,
)
from localstack.services.stepfunctions.asl.component.eval_component import EvalComponent
from localstack.services.stepfunctions.asl.eval.environment import Environment


class Parargs(EvalComponent, abc.ABC):
    template_eval_component: Final[EvalComponent]

    def __init__(self, template_eval_component: EvalComponent):
        self.template_eval_component = template_eval_component

    def _eval_body(self, env: Environment) -> None:
        self.template_eval_component.eval(env=env)


class Parameters(Parargs):
    def __init__(self, payload_tmpl: PayloadTmpl):
        super().__init__(template_eval_component=payload_tmpl)


class Arguments(Parargs, abc.ABC): ...


class ArgumentsJSONataTemplateValueObject(Arguments):
    def __init__(self, jsonata_template_value_object: JSONataTemplateValueObject):
        super().__init__(template_eval_component=jsonata_template_value_object)


class ArgumentsStringJSONata(Arguments):
    def __init__(self, string_jsonata: StringJSONata):
        super().__init__(template_eval_component=string_jsonata)
