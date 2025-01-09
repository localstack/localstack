import ast
from typing import Optional

from antlr4 import ParserRuleContext
from antlr4.tree.Tree import ParseTree, TerminalNodeImpl


def is_production(pt: ParseTree, rule_index: Optional[int] = None) -> Optional[ParserRuleContext]:
    if isinstance(pt, ParserRuleContext):
        prc = pt.getRuleContext()  # noqa
        if rule_index is not None:
            return prc if prc.getRuleIndex() == rule_index else None
        return prc
    return None


def is_terminal(pt: ParseTree, token_type: Optional[int] = None) -> Optional[TerminalNodeImpl]:
    if isinstance(pt, TerminalNodeImpl):
        if token_type is not None:
            return pt if pt.getSymbol().type == token_type else None
        return pt
    return None


def from_string_literal(parser_rule_context: ParserRuleContext) -> Optional[str]:
    string_literal = parser_rule_context.getText()
    if string_literal.startswith('"') and string_literal.endswith('"'):
        string_literal = string_literal[1:-1]
    # Interpret escape sequences into their character representations
    try:
        string_literal = ast.literal_eval(f'"{string_literal}"')
    except Exception:
        # Fallback if literal_eval fails
        pass
    return string_literal
