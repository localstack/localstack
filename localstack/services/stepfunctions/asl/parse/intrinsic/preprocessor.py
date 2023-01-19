from typing import Optional

from antlr4.tree.Tree import TerminalNodeImpl

from localstack.services.stepfunctions.asl.antlr.runtime.ASLIntrinsicLexer import ASLIntrinsicLexer
from localstack.services.stepfunctions.asl.antlr.runtime.ASLIntrinsicParser import (
    ASLIntrinsicParser,
)
from localstack.services.stepfunctions.asl.antlr.runtime.ASLIntrinsicParserVisitor import (
    ASLIntrinsicParserVisitor,
)
from localstack.services.stepfunctions.asl.antlt4utils.antlr4utils import Antlr4Utils
from localstack.services.stepfunctions.asl.component.intrinsic.component import Component
from localstack.services.stepfunctions.asl.component.intrinsic.member import (
    DollarMember,
    IdentifiedMember,
    Member,
)
from localstack.services.stepfunctions.asl.component.intrinsic.member_access import MemberAccess
from localstack.services.stepfunctions.asl.component.intrinsic.program import Program


class Preprocessor(ASLIntrinsicParserVisitor):
    def visitMember(self, ctx: ASLIntrinsicParser.MemberContext) -> Member:
        fst_child: Optional[TerminalNodeImpl] = Antlr4Utils.is_terminal(ctx.children[-1])
        if not fst_child:
            raise ValueError(f"Could not derive Member from compilation context '{ctx.getText()}'.")

        match fst_child.getSymbol().type:
            case ASLIntrinsicLexer.IDENTIFIER:
                return IdentifiedMember(identifier=fst_child.getText())
            case ASLIntrinsicLexer.DOLLAR:
                return DollarMember()

    def visitMember_access(self, ctx: ASLIntrinsicParser.Member_accessContext) -> MemberAccess:
        subject_member = self.visit(ctx.children[0])
        target_member = self.visit(ctx.children[-1])

        if not (isinstance(subject_member, Member) and isinstance(target_member, Member)):
            raise ValueError(
                f"Could not derive MemberAccess from declaration context '{ctx.getText()}'."
            )

        return MemberAccess(subject=subject_member, target=target_member)

    def visitCompilation_unit(self, ctx: ASLIntrinsicParser.Compilation_unitContext) -> Program:
        program = Program()
        for child in ctx.children:
            cmp = self.visit(child)
            if isinstance(cmp, Component):
                program.statements.append(cmp)
        return program
