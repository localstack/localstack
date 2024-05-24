from typing import Final

from localstack.services.stepfunctions.asl.component.common.payload.payloadvalue.payloadtmpl.payload_tmpl import (
    PayloadTmpl,
)
from localstack.services.stepfunctions.asl.component.eval_component import EvalComponent
from localstack.services.stepfunctions.asl.eval.environment import Environment


class Parameters(EvalComponent):
    payload_tmpl: Final[PayloadTmpl]

    def __init__(self, payload_tmpl: PayloadTmpl):
        self.payload_tmpl = payload_tmpl

    def _eval_body(self, env: Environment) -> None:
        self.payload_tmpl.eval(env=env)
