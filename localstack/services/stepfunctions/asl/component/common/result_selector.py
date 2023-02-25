import copy

from localstack.services.stepfunctions.asl.component.common.payload.payloadvalue.payloadtmpl.payload_tmpl import (
    PayloadTmpl,
)
from localstack.services.stepfunctions.asl.component.eval_component import EvalComponent
from localstack.services.stepfunctions.asl.eval.environment import Environment


class ResultSelector(EvalComponent):
    def __init__(self, payload_tmpl: PayloadTmpl):
        self.payload_tmpl: PayloadTmpl = payload_tmpl

    def _eval_body(self, env: Environment) -> None:
        inp_cache = copy.deepcopy(env.inp)

        env.inp = env.stack.pop()
        self.payload_tmpl.eval(env=env)

        env.inp = inp_cache
