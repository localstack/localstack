import abc
from typing import Final

from localstack.services.stepfunctions.asl.component.common.jsonata.jsonata_template_value import (
    JSONataTemplateValue,
)
from localstack.services.stepfunctions.asl.component.common.payload.payloadvalue.payloadtmpl.payload_tmpl import (
    PayloadTmpl,
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


class Arguments(Parargs):
    def __init__(self, jsonata_payload_value: JSONataTemplateValue):
        super().__init__(template_eval_component=jsonata_payload_value)
