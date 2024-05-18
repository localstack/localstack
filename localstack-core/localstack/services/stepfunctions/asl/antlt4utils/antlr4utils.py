from typing import Optional

from antlr4 import ParserRuleContext
from antlr4.tree.Tree import ParseTree, TerminalNodeImpl


class Antlr4Utils:
    @staticmethod
    def is_production(
        pt: ParseTree, rule_index: Optional[int] = None
    ) -> Optional[ParserRuleContext]:
        if isinstance(pt, ParserRuleContext):
            prc = pt.getRuleContext()  # noqa
            if rule_index is not None:
                return prc if prc.getRuleIndex() == rule_index else None
            return prc
        return None

    @staticmethod
    def is_terminal(pt: ParseTree, token_type: Optional[int] = None) -> Optional[TerminalNodeImpl]:
        if isinstance(pt, TerminalNodeImpl):
            if token_type is not None:
                return pt if pt.getSymbol().type == token_type else None
            return pt
        return None
