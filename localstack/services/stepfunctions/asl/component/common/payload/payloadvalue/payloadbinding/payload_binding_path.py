from typing import Any, Final

from localstack.services.stepfunctions.asl.component.common.payload.payloadvalue.payloadbinding.payload_binding import (
    PayloadBinding,
)
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.services.stepfunctions.asl.utils.json_path import JSONPathUtils


class PayloadBindingPath(PayloadBinding):
    def __init__(self, field: str, path: str):
        super().__init__(field=field)
        self.path: Final[str] = path

    @classmethod
    def from_raw(cls, string_dollar: str, string_path: str):
        field: str = string_dollar[:-2]
        return cls(field=field, path=string_path)

    def _eval_val(self, env: Environment) -> Any:
        value = JSONPathUtils.extract_json(self.path, env.inp)
        return value
