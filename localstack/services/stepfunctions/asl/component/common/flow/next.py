from typing import Final

from localstack.services.stepfunctions.asl.component.component import Component
from localstack.services.stepfunctions.asl.component.state.state_choice.choice_rule_stmt import (
    ChoiceRuleStmt,
)


class Next(ChoiceRuleStmt, Component):
    def __init__(self, name: str):
        # The name of the next state that is run when the current state finishes.
        self.name: Final[str] = name
