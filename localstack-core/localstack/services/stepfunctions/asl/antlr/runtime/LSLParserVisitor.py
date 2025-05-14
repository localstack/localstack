# Generated from LSLParser.g4 by ANTLR 4.13.2
from antlr4 import *
if "." in __name__:
    from .LSLParser import LSLParser
else:
    from LSLParser import LSLParser

# This class defines a complete generic visitor for a parse tree produced by LSLParser.

class LSLParserVisitor(ParseTreeVisitor):

    # Visit a parse tree produced by LSLParser#state_machine.
    def visitState_machine(self, ctx:LSLParser.State_machineContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by LSLParser#state_declaration.
    def visitState_declaration(self, ctx:LSLParser.State_declarationContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by LSLParser#state_call_template.
    def visitState_call_template(self, ctx:LSLParser.State_call_templateContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by LSLParser#state_call_named.
    def visitState_call_named(self, ctx:LSLParser.State_call_namedContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by LSLParser#state_call_anonymous.
    def visitState_call_anonymous(self, ctx:LSLParser.State_call_anonymousContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by LSLParser#state_task.
    def visitState_task(self, ctx:LSLParser.State_taskContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by LSLParser#state_fail.
    def visitState_fail(self, ctx:LSLParser.State_failContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by LSLParser#state_return.
    def visitState_return(self, ctx:LSLParser.State_returnContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by LSLParser#state_map.
    def visitState_map(self, ctx:LSLParser.State_mapContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by LSLParser#state_parallel.
    def visitState_parallel(self, ctx:LSLParser.State_parallelContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by LSLParser#service_name.
    def visitService_name(self, ctx:LSLParser.Service_nameContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by LSLParser#task_where.
    def visitTask_where(self, ctx:LSLParser.Task_whereContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by LSLParser#fail_where.
    def visitFail_where(self, ctx:LSLParser.Fail_whereContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by LSLParser#arguments.
    def visitArguments(self, ctx:LSLParser.ArgumentsContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by LSLParser#catch_block.
    def visitCatch_block(self, ctx:LSLParser.Catch_blockContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by LSLParser#catch_case.
    def visitCatch_case(self, ctx:LSLParser.Catch_caseContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by LSLParser#parameter_list.
    def visitParameter_list(self, ctx:LSLParser.Parameter_listContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by LSLParser#args_assign_list.
    def visitArgs_assign_list(self, ctx:LSLParser.Args_assign_listContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by LSLParser#args_assign.
    def visitArgs_assign(self, ctx:LSLParser.Args_assignContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by LSLParser#error.
    def visitError(self, ctx:LSLParser.ErrorContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by LSLParser#cause.
    def visitCause(self, ctx:LSLParser.CauseContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by LSLParser#process.
    def visitProcess(self, ctx:LSLParser.ProcessContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by LSLParser#var_assign_state_call.
    def visitVar_assign_state_call(self, ctx:LSLParser.Var_assign_state_callContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by LSLParser#var_assign_json_value.
    def visitVar_assign_json_value(self, ctx:LSLParser.Var_assign_json_valueContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by LSLParser#json_value.
    def visitJson_value(self, ctx:LSLParser.Json_valueContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by LSLParser#json_object.
    def visitJson_object(self, ctx:LSLParser.Json_objectContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by LSLParser#json_binding.
    def visitJson_binding(self, ctx:LSLParser.Json_bindingContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by LSLParser#json_arr.
    def visitJson_arr(self, ctx:LSLParser.Json_arrContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by LSLParser#json_value_float.
    def visitJson_value_float(self, ctx:LSLParser.Json_value_floatContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by LSLParser#json_value_int.
    def visitJson_value_int(self, ctx:LSLParser.Json_value_intContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by LSLParser#json_value_bool.
    def visitJson_value_bool(self, ctx:LSLParser.Json_value_boolContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by LSLParser#json_value_null.
    def visitJson_value_null(self, ctx:LSLParser.Json_value_nullContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by LSLParser#json_value_str.
    def visitJson_value_str(self, ctx:LSLParser.Json_value_strContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by LSLParser#json_value_jsonata.
    def visitJson_value_jsonata(self, ctx:LSLParser.Json_value_jsonataContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by LSLParser#string_or_jsonata_string.
    def visitString_or_jsonata_string(self, ctx:LSLParser.String_or_jsonata_stringContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by LSLParser#string_or_jsonata_jsonata.
    def visitString_or_jsonata_jsonata(self, ctx:LSLParser.String_or_jsonata_jsonataContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by LSLParser#error_name.
    def visitError_name(self, ctx:LSLParser.Error_nameContext):
        return self.visitChildren(ctx)



del LSLParser