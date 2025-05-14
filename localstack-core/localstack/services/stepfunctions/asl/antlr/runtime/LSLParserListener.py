# Generated from LSLParser.g4 by ANTLR 4.13.2
from antlr4 import *
if "." in __name__:
    from .LSLParser import LSLParser
else:
    from LSLParser import LSLParser

# This class defines a complete listener for a parse tree produced by LSLParser.
class LSLParserListener(ParseTreeListener):

    # Enter a parse tree produced by LSLParser#state_machine.
    def enterState_machine(self, ctx:LSLParser.State_machineContext):
        pass

    # Exit a parse tree produced by LSLParser#state_machine.
    def exitState_machine(self, ctx:LSLParser.State_machineContext):
        pass


    # Enter a parse tree produced by LSLParser#state_declaration.
    def enterState_declaration(self, ctx:LSLParser.State_declarationContext):
        pass

    # Exit a parse tree produced by LSLParser#state_declaration.
    def exitState_declaration(self, ctx:LSLParser.State_declarationContext):
        pass


    # Enter a parse tree produced by LSLParser#state_call_template.
    def enterState_call_template(self, ctx:LSLParser.State_call_templateContext):
        pass

    # Exit a parse tree produced by LSLParser#state_call_template.
    def exitState_call_template(self, ctx:LSLParser.State_call_templateContext):
        pass


    # Enter a parse tree produced by LSLParser#state_call_named.
    def enterState_call_named(self, ctx:LSLParser.State_call_namedContext):
        pass

    # Exit a parse tree produced by LSLParser#state_call_named.
    def exitState_call_named(self, ctx:LSLParser.State_call_namedContext):
        pass


    # Enter a parse tree produced by LSLParser#state_call_anonymous.
    def enterState_call_anonymous(self, ctx:LSLParser.State_call_anonymousContext):
        pass

    # Exit a parse tree produced by LSLParser#state_call_anonymous.
    def exitState_call_anonymous(self, ctx:LSLParser.State_call_anonymousContext):
        pass


    # Enter a parse tree produced by LSLParser#state_task.
    def enterState_task(self, ctx:LSLParser.State_taskContext):
        pass

    # Exit a parse tree produced by LSLParser#state_task.
    def exitState_task(self, ctx:LSLParser.State_taskContext):
        pass


    # Enter a parse tree produced by LSLParser#state_fail.
    def enterState_fail(self, ctx:LSLParser.State_failContext):
        pass

    # Exit a parse tree produced by LSLParser#state_fail.
    def exitState_fail(self, ctx:LSLParser.State_failContext):
        pass


    # Enter a parse tree produced by LSLParser#state_return.
    def enterState_return(self, ctx:LSLParser.State_returnContext):
        pass

    # Exit a parse tree produced by LSLParser#state_return.
    def exitState_return(self, ctx:LSLParser.State_returnContext):
        pass


    # Enter a parse tree produced by LSLParser#service_name.
    def enterService_name(self, ctx:LSLParser.Service_nameContext):
        pass

    # Exit a parse tree produced by LSLParser#service_name.
    def exitService_name(self, ctx:LSLParser.Service_nameContext):
        pass


    # Enter a parse tree produced by LSLParser#task_where.
    def enterTask_where(self, ctx:LSLParser.Task_whereContext):
        pass

    # Exit a parse tree produced by LSLParser#task_where.
    def exitTask_where(self, ctx:LSLParser.Task_whereContext):
        pass


    # Enter a parse tree produced by LSLParser#fail_where.
    def enterFail_where(self, ctx:LSLParser.Fail_whereContext):
        pass

    # Exit a parse tree produced by LSLParser#fail_where.
    def exitFail_where(self, ctx:LSLParser.Fail_whereContext):
        pass


    # Enter a parse tree produced by LSLParser#arguments.
    def enterArguments(self, ctx:LSLParser.ArgumentsContext):
        pass

    # Exit a parse tree produced by LSLParser#arguments.
    def exitArguments(self, ctx:LSLParser.ArgumentsContext):
        pass


    # Enter a parse tree produced by LSLParser#catch_block.
    def enterCatch_block(self, ctx:LSLParser.Catch_blockContext):
        pass

    # Exit a parse tree produced by LSLParser#catch_block.
    def exitCatch_block(self, ctx:LSLParser.Catch_blockContext):
        pass


    # Enter a parse tree produced by LSLParser#catch_case.
    def enterCatch_case(self, ctx:LSLParser.Catch_caseContext):
        pass

    # Exit a parse tree produced by LSLParser#catch_case.
    def exitCatch_case(self, ctx:LSLParser.Catch_caseContext):
        pass


    # Enter a parse tree produced by LSLParser#parameter_list.
    def enterParameter_list(self, ctx:LSLParser.Parameter_listContext):
        pass

    # Exit a parse tree produced by LSLParser#parameter_list.
    def exitParameter_list(self, ctx:LSLParser.Parameter_listContext):
        pass


    # Enter a parse tree produced by LSLParser#args_assign_list.
    def enterArgs_assign_list(self, ctx:LSLParser.Args_assign_listContext):
        pass

    # Exit a parse tree produced by LSLParser#args_assign_list.
    def exitArgs_assign_list(self, ctx:LSLParser.Args_assign_listContext):
        pass


    # Enter a parse tree produced by LSLParser#args_assign.
    def enterArgs_assign(self, ctx:LSLParser.Args_assignContext):
        pass

    # Exit a parse tree produced by LSLParser#args_assign.
    def exitArgs_assign(self, ctx:LSLParser.Args_assignContext):
        pass


    # Enter a parse tree produced by LSLParser#error.
    def enterError(self, ctx:LSLParser.ErrorContext):
        pass

    # Exit a parse tree produced by LSLParser#error.
    def exitError(self, ctx:LSLParser.ErrorContext):
        pass


    # Enter a parse tree produced by LSLParser#cause.
    def enterCause(self, ctx:LSLParser.CauseContext):
        pass

    # Exit a parse tree produced by LSLParser#cause.
    def exitCause(self, ctx:LSLParser.CauseContext):
        pass


    # Enter a parse tree produced by LSLParser#var_assign_state_call.
    def enterVar_assign_state_call(self, ctx:LSLParser.Var_assign_state_callContext):
        pass

    # Exit a parse tree produced by LSLParser#var_assign_state_call.
    def exitVar_assign_state_call(self, ctx:LSLParser.Var_assign_state_callContext):
        pass


    # Enter a parse tree produced by LSLParser#var_assign_json_value.
    def enterVar_assign_json_value(self, ctx:LSLParser.Var_assign_json_valueContext):
        pass

    # Exit a parse tree produced by LSLParser#var_assign_json_value.
    def exitVar_assign_json_value(self, ctx:LSLParser.Var_assign_json_valueContext):
        pass


    # Enter a parse tree produced by LSLParser#json_value.
    def enterJson_value(self, ctx:LSLParser.Json_valueContext):
        pass

    # Exit a parse tree produced by LSLParser#json_value.
    def exitJson_value(self, ctx:LSLParser.Json_valueContext):
        pass


    # Enter a parse tree produced by LSLParser#json_object.
    def enterJson_object(self, ctx:LSLParser.Json_objectContext):
        pass

    # Exit a parse tree produced by LSLParser#json_object.
    def exitJson_object(self, ctx:LSLParser.Json_objectContext):
        pass


    # Enter a parse tree produced by LSLParser#json_binding.
    def enterJson_binding(self, ctx:LSLParser.Json_bindingContext):
        pass

    # Exit a parse tree produced by LSLParser#json_binding.
    def exitJson_binding(self, ctx:LSLParser.Json_bindingContext):
        pass


    # Enter a parse tree produced by LSLParser#json_arr.
    def enterJson_arr(self, ctx:LSLParser.Json_arrContext):
        pass

    # Exit a parse tree produced by LSLParser#json_arr.
    def exitJson_arr(self, ctx:LSLParser.Json_arrContext):
        pass


    # Enter a parse tree produced by LSLParser#json_value_float.
    def enterJson_value_float(self, ctx:LSLParser.Json_value_floatContext):
        pass

    # Exit a parse tree produced by LSLParser#json_value_float.
    def exitJson_value_float(self, ctx:LSLParser.Json_value_floatContext):
        pass


    # Enter a parse tree produced by LSLParser#json_value_int.
    def enterJson_value_int(self, ctx:LSLParser.Json_value_intContext):
        pass

    # Exit a parse tree produced by LSLParser#json_value_int.
    def exitJson_value_int(self, ctx:LSLParser.Json_value_intContext):
        pass


    # Enter a parse tree produced by LSLParser#json_value_bool.
    def enterJson_value_bool(self, ctx:LSLParser.Json_value_boolContext):
        pass

    # Exit a parse tree produced by LSLParser#json_value_bool.
    def exitJson_value_bool(self, ctx:LSLParser.Json_value_boolContext):
        pass


    # Enter a parse tree produced by LSLParser#json_value_null.
    def enterJson_value_null(self, ctx:LSLParser.Json_value_nullContext):
        pass

    # Exit a parse tree produced by LSLParser#json_value_null.
    def exitJson_value_null(self, ctx:LSLParser.Json_value_nullContext):
        pass


    # Enter a parse tree produced by LSLParser#json_value_str.
    def enterJson_value_str(self, ctx:LSLParser.Json_value_strContext):
        pass

    # Exit a parse tree produced by LSLParser#json_value_str.
    def exitJson_value_str(self, ctx:LSLParser.Json_value_strContext):
        pass


    # Enter a parse tree produced by LSLParser#json_value_jsonata.
    def enterJson_value_jsonata(self, ctx:LSLParser.Json_value_jsonataContext):
        pass

    # Exit a parse tree produced by LSLParser#json_value_jsonata.
    def exitJson_value_jsonata(self, ctx:LSLParser.Json_value_jsonataContext):
        pass


    # Enter a parse tree produced by LSLParser#string_or_jsonata_string.
    def enterString_or_jsonata_string(self, ctx:LSLParser.String_or_jsonata_stringContext):
        pass

    # Exit a parse tree produced by LSLParser#string_or_jsonata_string.
    def exitString_or_jsonata_string(self, ctx:LSLParser.String_or_jsonata_stringContext):
        pass


    # Enter a parse tree produced by LSLParser#string_or_jsonata_jsonata.
    def enterString_or_jsonata_jsonata(self, ctx:LSLParser.String_or_jsonata_jsonataContext):
        pass

    # Exit a parse tree produced by LSLParser#string_or_jsonata_jsonata.
    def exitString_or_jsonata_jsonata(self, ctx:LSLParser.String_or_jsonata_jsonataContext):
        pass


    # Enter a parse tree produced by LSLParser#error_name.
    def enterError_name(self, ctx:LSLParser.Error_nameContext):
        pass

    # Exit a parse tree produced by LSLParser#error_name.
    def exitError_name(self, ctx:LSLParser.Error_nameContext):
        pass



del LSLParser