from localstack.services.stepfunctions.asl.component.common.payload.payloadvalue.payloadvaluelit.payload_value_lit import (
    PayloadValueLit,
)


class PayloadValueInt(PayloadValueLit):
    val: int

    def __init__(self, val: int):
        super().__init__(val=val)
