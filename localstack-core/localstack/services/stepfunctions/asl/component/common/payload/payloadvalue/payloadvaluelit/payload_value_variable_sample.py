from typing import Final

from localstack.services.stepfunctions.asl.component.common.payload.payloadvalue.payload_value import (
    PayloadValue,
)
from localstack.services.stepfunctions.asl.component.common.variable_sample import VariableSample
from localstack.services.stepfunctions.asl.eval.environment import Environment


class PayloadValueVariableSample(PayloadValue):
    variable_sample: Final[VariableSample]

    def __init__(self, variable_sample: VariableSample):
        super().__init__()
        self.variable_sample = variable_sample

    def _eval_body(self, env: Environment) -> None:
        self.variable_sample.eval(env=env)
