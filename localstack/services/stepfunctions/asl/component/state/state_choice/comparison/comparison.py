from typing import Final

from localstack.services.stepfunctions.asl.component.state.state_choice.choice_rule_stmt import (
    ChoiceRuleStmt,
)
from localstack.services.stepfunctions.asl.component.state.state_choice.comparison.comparison_func import (
    ComparisonFunc,
)
from localstack.services.stepfunctions.asl.component.state.state_choice.comparison.comparison_stmt import (
    ComparisonStmt,
)
from localstack.services.stepfunctions.asl.component.state.state_wait.variable import Variable
from localstack.services.stepfunctions.asl.eval.environment import Environment


class Comparison(ComparisonStmt, ChoiceRuleStmt):
    def __init__(self, variable: Variable, func: ComparisonFunc):
        self.variable: Final[Variable] = variable
        self.function: Final[ComparisonFunc] = func

    def _eval_body(self, env: Environment) -> None:
        variable: Variable = self.variable
        variable.eval(env)
        function: ComparisonFunc = self.function
        function.eval(env)
