from __future__ import annotations

import abc
from enum import Enum
from typing import Any, Final

from localstack.services.stepfunctions.asl.antlr.runtime.ASLLexer import ASLLexer
from localstack.services.stepfunctions.asl.component.state.state_choice.choice_rule import (
    ChoiceRule,
)
from localstack.services.stepfunctions.asl.component.state.state_choice.comparison.comparison import (
    Comparison,
)
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.services.stepfunctions.asl.parse.typed_props import TypedProps


class ComparisonCompositeProps(TypedProps):
    def add(self, instance: Any) -> None:
        inst_type = type(instance)

        if issubclass(inst_type, ComparisonComposite):
            super()._add(ComparisonComposite, instance)
            return

        super().add(instance)


class ComparisonComposite(Comparison, abc.ABC):
    class ChoiceOp(Enum):
        And = ASLLexer.AND
        Or = ASLLexer.OR
        Not = ASLLexer.NOT

    operator: Final[ComparisonComposite.ChoiceOp]

    def __init__(self, operator: ComparisonComposite.ChoiceOp):
        self.operator = operator


class ComparisonCompositeSingle(ComparisonComposite, abc.ABC):
    rule: Final[ChoiceRule]

    def __init__(self, operator: ComparisonComposite.ChoiceOp, rule: ChoiceRule):
        super(ComparisonCompositeSingle, self).__init__(operator=operator)
        self.rule = rule


class ComparisonCompositeMulti(ComparisonComposite, abc.ABC):
    rules: Final[list[ChoiceRule]]

    def __init__(self, operator: ComparisonComposite.ChoiceOp, rules: list[ChoiceRule]):
        super(ComparisonCompositeMulti, self).__init__(operator=operator)
        self.rules = rules


class ComparisonCompositeNot(ComparisonCompositeSingle):
    def __init__(self, rule: ChoiceRule):
        super(ComparisonCompositeNot, self).__init__(
            operator=ComparisonComposite.ChoiceOp.Not, rule=rule
        )

    def _eval_body(self, env: Environment) -> None:
        self.rule.eval(env)
        tmp: bool = env.stack.pop()
        res = tmp is False
        env.stack.append(res)


class ComparisonCompositeAnd(ComparisonCompositeMulti):
    def __init__(self, rules: list[ChoiceRule]):
        super(ComparisonCompositeAnd, self).__init__(
            operator=ComparisonComposite.ChoiceOp.And, rules=rules
        )

    def _eval_body(self, env: Environment) -> None:
        res = True
        for rule in self.rules:
            rule.eval(env)
            rule_out = env.stack.pop()
            if not rule_out:
                res = False
                break  # TODO: Lazy evaluation? Can use all function instead? how's eval for that?
        env.stack.append(res)


class ComparisonCompositeOr(ComparisonCompositeMulti):
    def __init__(self, rules: list[ChoiceRule]):
        super(ComparisonCompositeOr, self).__init__(
            operator=ComparisonComposite.ChoiceOp.Or, rules=rules
        )

    def _eval_body(self, env: Environment) -> None:
        res = False
        for rule in self.rules:
            rule.eval(env)
            rule_out = env.stack.pop()
            res = res or rule_out
            if res:
                break  # TODO: Lazy evaluation? Can use all function instead? how's eval for that?
        env.stack.append(res)
