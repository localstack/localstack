from typing import Optional

from localstack.services.stepfunctions.asl.component.state.state_choice.comparison.comparison_func import (
    ComparisonFunc,
)
from localstack.services.stepfunctions.asl.component.state.state_wait.variable import Variable


class ComparisonProps:
    def __init__(self):
        self._variable: Optional[Variable] = None
        self._function: Optional[ComparisonFunc] = None

    @property
    def variable(self) -> Optional[Variable]:
        return self._variable

    @variable.setter
    def variable(self, variable: Variable) -> None:
        if self._variable:
            raise ValueError(f"Variable redefinition: from {self._variable} to {variable}")
        self._variable = variable

    @property
    def function(self) -> Optional[ComparisonFunc]:
        return self._function

    @function.setter
    def function(self, function: ComparisonFunc) -> None:
        if self._function:
            raise ValueError(f"ComparisonFunc redefinition: from {self._function} to {function}")
        self._function = function
