from typing import Any, Final

from localstack.services.stepfunctions.asl.component.common.payload.payloadvalue.payloadbinding.payload_binding import (
    PayloadBinding,
)


class PayloadBindingIntrinsicFunc(PayloadBinding):
    def __init__(self, field: str, intrinsic_func: str):
        super().__init__(field=field)
        self.intrinsic_func: Final[str] = intrinsic_func

    @classmethod
    def from_raw(cls, string_dollar: str, intrinsic_func: str):
        field: str = string_dollar[:-2]
        return cls(field=field, intrinsic_func=intrinsic_func)

    def _eval_val(self) -> Any:
        # TODO: raise unsupported here.
        return self.intrinsic_func
