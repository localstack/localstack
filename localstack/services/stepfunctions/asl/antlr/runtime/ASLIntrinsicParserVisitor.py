# Generated from /Users/mep/LocalStack/localstack/localstack/services/stepfunctions/asl/antlr/ASLIntrinsicParser.g4 by ANTLR 4.11.1
from antlr4 import *
if __name__ is not None and "." in __name__:
    from .ASLIntrinsicParser import ASLIntrinsicParser
else:
    from ASLIntrinsicParser import ASLIntrinsicParser

# This class defines a complete generic visitor for a parse tree produced by ASLIntrinsicParser.

class ASLIntrinsicParserVisitor(ParseTreeVisitor):

    # Visit a parse tree produced by ASLIntrinsicParser#compilation_unit.
    def visitCompilation_unit(self, ctx:ASLIntrinsicParser.Compilation_unitContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLIntrinsicParser#member_access.
    def visitMember_access(self, ctx:ASLIntrinsicParser.Member_accessContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLIntrinsicParser#member.
    def visitMember(self, ctx:ASLIntrinsicParser.MemberContext):
        return self.visitChildren(ctx)



del ASLIntrinsicParser