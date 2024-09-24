import abc
from typing import Any, Optional

from localstack.services.stepfunctions.asl.component.eval_component import EvalComponent
from localstack.services.stepfunctions.asl.eval.environment import Environment


class FunctionArgument(EvalComponent, abc.ABC):
    _value: Optional[Any]

    def __init__(self, value: Any = None):
        self._value = value

    def _eval_body(self, env: Environment) -> None:
        env.stack.append(self._value)
