from localstack.services.stepfunctions.asl.component.common.payload.payloadvalue.payloadvaluelit.payload_value_lit import (
    PayloadValueLit,
)


class PayloadValueNull(PayloadValueLit):
    val: None

    def __init__(self):
        super().__init__(val=None)
