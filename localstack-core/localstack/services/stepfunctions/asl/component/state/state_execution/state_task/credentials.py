from typing import Final

from localstack.services.stepfunctions.asl.component.common.payload.payloadvalue.payloadtmpl.payload_tmpl import (
    PayloadTmpl,
)
from localstack.services.stepfunctions.asl.component.eval_component import EvalComponent
from localstack.services.stepfunctions.asl.eval.environment import Environment


class Credentials(EvalComponent):
    payload_template: Final[PayloadTmpl]

    def __init__(self, payload_template: PayloadTmpl):
        self.payload_template = payload_template

    def _eval_body(self, env: Environment) -> None:
        self.payload_template.eval(env=env)
