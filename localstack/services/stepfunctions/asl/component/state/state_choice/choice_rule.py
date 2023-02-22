from typing import Optional

from localstack.services.stepfunctions.asl.component.common.flow.next import Next
from localstack.services.stepfunctions.asl.component.eval_component import EvalComponent
from localstack.services.stepfunctions.asl.component.state.state_choice.choice_rule_stmt import (
    ChoiceRuleStmt,
)
from localstack.services.stepfunctions.asl.component.state.state_choice.comparison.comparison_stmt import (
    ComparisonStmt,
)
from localstack.services.stepfunctions.asl.eval.environment import Environment


class ChoiceRule(EvalComponent):
    def __init__(self, stmts: list[ChoiceRuleStmt]):
        self.comparison: Optional[ComparisonStmt] = None
        self.next: Optional[Next] = None

        for stmt in stmts:
            if isinstance(stmt, ComparisonStmt):
                if self.comparison:
                    raise ValueError(
                        f"Comparison redefinition for ChoiceRule with ChoiceRuleStmt list '{stmts}'."
                    )
                self.comparison = stmt
            elif isinstance(stmt, Next):
                if self.next:
                    raise ValueError(
                        f"Next redefinition for ChoiceRule with ChoiceRuleStmt list '{stmts}'."
                    )
                self.next = stmt
            else:
                raise ValueError(
                    f"Invalid ChoiceRuleStmt type '{type(stmt)}' ChoiceRule with ChoiceRuleStmt list '{stmts}'."
                )

    def _eval_body(self, env: Environment) -> None:
        self.comparison.eval(env)
