# Generated from ASLIntrinsicParser.g4 by ANTLR 4.13.2
from antlr4 import *
if "." in __name__:
    from .ASLIntrinsicParser import ASLIntrinsicParser
else:
    from ASLIntrinsicParser import ASLIntrinsicParser

# This class defines a complete generic visitor for a parse tree produced by ASLIntrinsicParser.

class ASLIntrinsicParserVisitor(ParseTreeVisitor):

    # Visit a parse tree produced by ASLIntrinsicParser#func_decl.
    def visitFunc_decl(self, ctx:ASLIntrinsicParser.Func_declContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLIntrinsicParser#states_func_decl.
    def visitStates_func_decl(self, ctx:ASLIntrinsicParser.States_func_declContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLIntrinsicParser#state_fun_name.
    def visitState_fun_name(self, ctx:ASLIntrinsicParser.State_fun_nameContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLIntrinsicParser#func_arg_list.
    def visitFunc_arg_list(self, ctx:ASLIntrinsicParser.Func_arg_listContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLIntrinsicParser#func_arg_string.
    def visitFunc_arg_string(self, ctx:ASLIntrinsicParser.Func_arg_stringContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLIntrinsicParser#func_arg_int.
    def visitFunc_arg_int(self, ctx:ASLIntrinsicParser.Func_arg_intContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLIntrinsicParser#func_arg_float.
    def visitFunc_arg_float(self, ctx:ASLIntrinsicParser.Func_arg_floatContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLIntrinsicParser#func_arg_bool.
    def visitFunc_arg_bool(self, ctx:ASLIntrinsicParser.Func_arg_boolContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLIntrinsicParser#func_arg_context_path.
    def visitFunc_arg_context_path(self, ctx:ASLIntrinsicParser.Func_arg_context_pathContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLIntrinsicParser#func_arg_json_path.
    def visitFunc_arg_json_path(self, ctx:ASLIntrinsicParser.Func_arg_json_pathContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLIntrinsicParser#func_arg_var.
    def visitFunc_arg_var(self, ctx:ASLIntrinsicParser.Func_arg_varContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLIntrinsicParser#func_arg_func_decl.
    def visitFunc_arg_func_decl(self, ctx:ASLIntrinsicParser.Func_arg_func_declContext):
        return self.visitChildren(ctx)



del ASLIntrinsicParser