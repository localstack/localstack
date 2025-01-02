import abc
from typing import Any, Final, Optional

from localstack.services.stepfunctions.asl.component.common.payload.payloadvalue.payload_value import (
    PayloadValue,
)
from localstack.services.stepfunctions.asl.component.common.string.string_expression import (
    StringExpressionSimple,
)
from localstack.services.stepfunctions.asl.eval.environment import Environment


class PayloadBinding(PayloadValue, abc.ABC):
    field: Final[str]

    def __init__(self, field: str):
        self.field = field

    def _field_name(self) -> Optional[str]:
        return self.field

    @abc.abstractmethod
    def _eval_val(self, env: Environment) -> Any: ...

    def _eval_body(self, env: Environment) -> None:
        cnt: dict = env.stack.pop()
        val = self._eval_val(env=env)
        cnt[self.field] = val
        env.stack.append(cnt)


class PayloadBindingStringExpressionSimple(PayloadBinding):
    string_expression_simple: Final[StringExpressionSimple]

    def __init__(self, field: str, string_expression_simple: StringExpressionSimple):
        super().__init__(field=field)
        self.string_expression_simple = string_expression_simple

    def _field_name(self) -> Optional[str]:
        return f"{self.field}.$"

    def _eval_val(self, env: Environment) -> Any:
        self.string_expression_simple.eval(env=env)
        value = env.stack.pop()
        return value


class PayloadBindingValue(PayloadBinding):
    payload_value: Final[PayloadValue]

    def __init__(self, field: str, payload_value: PayloadValue):
        super().__init__(field=field)
        self.payload_value = payload_value

    def _eval_val(self, env: Environment) -> Any:
        self.payload_value.eval(env)
        val: Any = env.stack.pop()
        return val
