# Generated from /Users/mep/LocalStack/localstack/localstack/services/stepfunctions/asl/antlr/ASLIntrinsicParser.g4 by ANTLR 4.12.0
from antlr4 import *
if __name__ is not None and "." in __name__:
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


    # Visit a parse tree produced by ASLIntrinsicParser#func_arg_json_path.
    def visitFunc_arg_json_path(self, ctx:ASLIntrinsicParser.Func_arg_json_pathContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLIntrinsicParser#func_arg_func_decl.
    def visitFunc_arg_func_decl(self, ctx:ASLIntrinsicParser.Func_arg_func_declContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLIntrinsicParser#json_path.
    def visitJson_path(self, ctx:ASLIntrinsicParser.Json_pathContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLIntrinsicParser#json_path_part.
    def visitJson_path_part(self, ctx:ASLIntrinsicParser.Json_path_partContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLIntrinsicParser#json_path_iden.
    def visitJson_path_iden(self, ctx:ASLIntrinsicParser.Json_path_idenContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLIntrinsicParser#json_path_iden_qual.
    def visitJson_path_iden_qual(self, ctx:ASLIntrinsicParser.Json_path_iden_qualContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLIntrinsicParser#json_path_qual_void.
    def visitJson_path_qual_void(self, ctx:ASLIntrinsicParser.Json_path_qual_voidContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLIntrinsicParser#json_path_qual_idx.
    def visitJson_path_qual_idx(self, ctx:ASLIntrinsicParser.Json_path_qual_idxContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLIntrinsicParser#json_path_qual_query.
    def visitJson_path_qual_query(self, ctx:ASLIntrinsicParser.Json_path_qual_queryContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLIntrinsicParser#json_path_query_cmp.
    def visitJson_path_query_cmp(self, ctx:ASLIntrinsicParser.Json_path_query_cmpContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLIntrinsicParser#json_path_query_length.
    def visitJson_path_query_length(self, ctx:ASLIntrinsicParser.Json_path_query_lengthContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLIntrinsicParser#json_path_query_binary.
    def visitJson_path_query_binary(self, ctx:ASLIntrinsicParser.Json_path_query_binaryContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLIntrinsicParser#json_path_query_star.
    def visitJson_path_query_star(self, ctx:ASLIntrinsicParser.Json_path_query_starContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLIntrinsicParser#identifier.
    def visitIdentifier(self, ctx:ASLIntrinsicParser.IdentifierContext):
        return self.visitChildren(ctx)



del ASLIntrinsicParser