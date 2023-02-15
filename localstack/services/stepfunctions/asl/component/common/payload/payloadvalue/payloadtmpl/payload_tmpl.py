from typing import Final

from localstack.services.stepfunctions.asl.component.common.payload.payloadvalue.payload_value import (
    PayloadValue,
)
from localstack.services.stepfunctions.asl.component.common.payload.payloadvalue.payloadbinding.payload_binding import (
    PayloadBinding,
)
from localstack.services.stepfunctions.asl.eval.environment import Environment


class PayloadTmpl(PayloadValue):
    def __init__(self, payload_bindings: list[PayloadBinding]):
        self.payload_bindings: Final[list[PayloadBinding]] = payload_bindings

    def _eval_body(self, env: Environment) -> None:
        env.stack.append(dict())
        for payload_binding in self.payload_bindings:
            payload_binding.eval(env)
