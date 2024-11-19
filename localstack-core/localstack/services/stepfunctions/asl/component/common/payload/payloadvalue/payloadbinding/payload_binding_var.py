from typing import Any, Final

from localstack.services.stepfunctions.asl.component.common.payload.payloadvalue.payloadbinding.payload_binding import (
    PayloadBinding,
)
from localstack.services.stepfunctions.asl.component.common.variable_sample import VariableSample
from localstack.services.stepfunctions.asl.eval.environment import Environment


class PayloadBindingVar(PayloadBinding):
    variable_sample: Final[VariableSample]

    def __init__(self, field: str, variable_sample: VariableSample):
        super().__init__(field=field)
        self.variable_sample = variable_sample

    @classmethod
    def from_raw(cls, string_dollar: str, variable_sample: VariableSample):
        field: str = string_dollar[:-2]
        return cls(field=field, variable_sample=variable_sample)

    def _eval_val(self, env: Environment) -> Any:
        self.variable_sample.eval(env=env)
        value = env.stack.pop()
        return value
