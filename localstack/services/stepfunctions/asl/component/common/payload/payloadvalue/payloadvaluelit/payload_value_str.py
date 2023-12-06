from localstack.services.stepfunctions.asl.component.common.payload.payloadvalue.payloadvaluelit.payload_value_lit import (
    PayloadValueLit,
)


class PayloadValueStr(PayloadValueLit):
    val: str

    def __init__(self, val: str):
        super().__init__(val=val)
