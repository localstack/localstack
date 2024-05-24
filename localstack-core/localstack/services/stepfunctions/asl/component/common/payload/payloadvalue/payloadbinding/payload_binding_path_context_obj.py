from typing import Any, Final

from localstack.services.stepfunctions.asl.component.common.payload.payloadvalue.payloadbinding.payload_binding import (
    PayloadBinding,
)
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.services.stepfunctions.asl.utils.json_path import JSONPathUtils


class PayloadBindingPathContextObj(PayloadBinding):
    def __init__(self, field: str, path_context_obj: str):
        super().__init__(field=field)
        self.path_context_obj: Final[str] = path_context_obj

    @classmethod
    def from_raw(cls, string_dollar: str, string_path_context_obj: str):
        field: str = string_dollar[:-2]
        path_context_obj: str = string_path_context_obj[1:]
        return cls(field=field, path_context_obj=path_context_obj)

    def _eval_val(self, env: Environment) -> Any:
        value = JSONPathUtils.extract_json(
            self.path_context_obj, env.context_object_manager.context_object
        )
        return value
