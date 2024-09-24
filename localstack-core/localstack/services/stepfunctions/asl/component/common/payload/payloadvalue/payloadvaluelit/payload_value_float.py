from localstack.services.stepfunctions.asl.component.common.payload.payloadvalue.payloadvaluelit.payload_value_lit import (
    PayloadValueLit,
)


class PayloadValueFloat(PayloadValueLit):
    val: float

    def __init__(self, val: float):
        super().__init__(val=val)
