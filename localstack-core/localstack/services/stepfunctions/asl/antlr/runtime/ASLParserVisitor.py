# Generated from ASLParser.g4 by ANTLR 4.13.2
from antlr4 import *
if "." in __name__:
    from .ASLParser import ASLParser
else:
    from ASLParser import ASLParser

# This class defines a complete generic visitor for a parse tree produced by ASLParser.

class ASLParserVisitor(ParseTreeVisitor):

    # Visit a parse tree produced by ASLParser#state_machine.
    def visitState_machine(self, ctx:ASLParser.State_machineContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#program_decl.
    def visitProgram_decl(self, ctx:ASLParser.Program_declContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#top_layer_stmt.
    def visitTop_layer_stmt(self, ctx:ASLParser.Top_layer_stmtContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#startat_decl.
    def visitStartat_decl(self, ctx:ASLParser.Startat_declContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#comment_decl.
    def visitComment_decl(self, ctx:ASLParser.Comment_declContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#version_decl.
    def visitVersion_decl(self, ctx:ASLParser.Version_declContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#query_language_decl.
    def visitQuery_language_decl(self, ctx:ASLParser.Query_language_declContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#state_stmt.
    def visitState_stmt(self, ctx:ASLParser.State_stmtContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#states_decl.
    def visitStates_decl(self, ctx:ASLParser.States_declContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#state_decl.
    def visitState_decl(self, ctx:ASLParser.State_declContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#state_decl_body.
    def visitState_decl_body(self, ctx:ASLParser.State_decl_bodyContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#type_decl.
    def visitType_decl(self, ctx:ASLParser.Type_declContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#next_decl.
    def visitNext_decl(self, ctx:ASLParser.Next_declContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#resource_decl.
    def visitResource_decl(self, ctx:ASLParser.Resource_declContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#input_path_decl.
    def visitInput_path_decl(self, ctx:ASLParser.Input_path_declContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#result_decl.
    def visitResult_decl(self, ctx:ASLParser.Result_declContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#result_path_decl.
    def visitResult_path_decl(self, ctx:ASLParser.Result_path_declContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#output_path_decl.
    def visitOutput_path_decl(self, ctx:ASLParser.Output_path_declContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#end_decl.
    def visitEnd_decl(self, ctx:ASLParser.End_declContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#default_decl.
    def visitDefault_decl(self, ctx:ASLParser.Default_declContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#error.
    def visitError(self, ctx:ASLParser.ErrorContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#error_path.
    def visitError_path(self, ctx:ASLParser.Error_pathContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#cause.
    def visitCause(self, ctx:ASLParser.CauseContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#cause_path.
    def visitCause_path(self, ctx:ASLParser.Cause_pathContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#seconds_jsonata.
    def visitSeconds_jsonata(self, ctx:ASLParser.Seconds_jsonataContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#seconds_int.
    def visitSeconds_int(self, ctx:ASLParser.Seconds_intContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#seconds_path.
    def visitSeconds_path(self, ctx:ASLParser.Seconds_pathContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#timestamp.
    def visitTimestamp(self, ctx:ASLParser.TimestampContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#timestamp_path.
    def visitTimestamp_path(self, ctx:ASLParser.Timestamp_pathContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#items_array.
    def visitItems_array(self, ctx:ASLParser.Items_arrayContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#items_jsonata.
    def visitItems_jsonata(self, ctx:ASLParser.Items_jsonataContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#items_path_decl.
    def visitItems_path_decl(self, ctx:ASLParser.Items_path_declContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#max_concurrency_jsonata.
    def visitMax_concurrency_jsonata(self, ctx:ASLParser.Max_concurrency_jsonataContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#max_concurrency_int.
    def visitMax_concurrency_int(self, ctx:ASLParser.Max_concurrency_intContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#max_concurrency_path.
    def visitMax_concurrency_path(self, ctx:ASLParser.Max_concurrency_pathContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#parameters_decl.
    def visitParameters_decl(self, ctx:ASLParser.Parameters_declContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#credentials_decl.
    def visitCredentials_decl(self, ctx:ASLParser.Credentials_declContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#role_arn.
    def visitRole_arn(self, ctx:ASLParser.Role_arnContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#role_path.
    def visitRole_path(self, ctx:ASLParser.Role_pathContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#timeout_seconds_jsonata.
    def visitTimeout_seconds_jsonata(self, ctx:ASLParser.Timeout_seconds_jsonataContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#timeout_seconds_int.
    def visitTimeout_seconds_int(self, ctx:ASLParser.Timeout_seconds_intContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#timeout_seconds_path.
    def visitTimeout_seconds_path(self, ctx:ASLParser.Timeout_seconds_pathContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#heartbeat_seconds_jsonata.
    def visitHeartbeat_seconds_jsonata(self, ctx:ASLParser.Heartbeat_seconds_jsonataContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#heartbeat_seconds_int.
    def visitHeartbeat_seconds_int(self, ctx:ASLParser.Heartbeat_seconds_intContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#heartbeat_seconds_path.
    def visitHeartbeat_seconds_path(self, ctx:ASLParser.Heartbeat_seconds_pathContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#payload_tmpl_decl.
    def visitPayload_tmpl_decl(self, ctx:ASLParser.Payload_tmpl_declContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#payload_binding_sample.
    def visitPayload_binding_sample(self, ctx:ASLParser.Payload_binding_sampleContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#payload_binding_value.
    def visitPayload_binding_value(self, ctx:ASLParser.Payload_binding_valueContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#payload_arr_decl.
    def visitPayload_arr_decl(self, ctx:ASLParser.Payload_arr_declContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#payload_value_decl.
    def visitPayload_value_decl(self, ctx:ASLParser.Payload_value_declContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#payload_value_float.
    def visitPayload_value_float(self, ctx:ASLParser.Payload_value_floatContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#payload_value_int.
    def visitPayload_value_int(self, ctx:ASLParser.Payload_value_intContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#payload_value_bool.
    def visitPayload_value_bool(self, ctx:ASLParser.Payload_value_boolContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#payload_value_null.
    def visitPayload_value_null(self, ctx:ASLParser.Payload_value_nullContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#payload_value_str.
    def visitPayload_value_str(self, ctx:ASLParser.Payload_value_strContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#assign_decl.
    def visitAssign_decl(self, ctx:ASLParser.Assign_declContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#assign_decl_body.
    def visitAssign_decl_body(self, ctx:ASLParser.Assign_decl_bodyContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#assign_decl_binding.
    def visitAssign_decl_binding(self, ctx:ASLParser.Assign_decl_bindingContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#assign_template_value_object.
    def visitAssign_template_value_object(self, ctx:ASLParser.Assign_template_value_objectContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#assign_template_binding_string_expression_simple.
    def visitAssign_template_binding_string_expression_simple(self, ctx:ASLParser.Assign_template_binding_string_expression_simpleContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#assign_template_binding_value.
    def visitAssign_template_binding_value(self, ctx:ASLParser.Assign_template_binding_valueContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#assign_template_value.
    def visitAssign_template_value(self, ctx:ASLParser.Assign_template_valueContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#assign_template_value_array.
    def visitAssign_template_value_array(self, ctx:ASLParser.Assign_template_value_arrayContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#assign_template_value_terminal_float.
    def visitAssign_template_value_terminal_float(self, ctx:ASLParser.Assign_template_value_terminal_floatContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#assign_template_value_terminal_int.
    def visitAssign_template_value_terminal_int(self, ctx:ASLParser.Assign_template_value_terminal_intContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#assign_template_value_terminal_bool.
    def visitAssign_template_value_terminal_bool(self, ctx:ASLParser.Assign_template_value_terminal_boolContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#assign_template_value_terminal_null.
    def visitAssign_template_value_terminal_null(self, ctx:ASLParser.Assign_template_value_terminal_nullContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#assign_template_value_terminal_string_jsonata.
    def visitAssign_template_value_terminal_string_jsonata(self, ctx:ASLParser.Assign_template_value_terminal_string_jsonataContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#assign_template_value_terminal_string_literal.
    def visitAssign_template_value_terminal_string_literal(self, ctx:ASLParser.Assign_template_value_terminal_string_literalContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#arguments_jsonata_template_value_object.
    def visitArguments_jsonata_template_value_object(self, ctx:ASLParser.Arguments_jsonata_template_value_objectContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#arguments_string_jsonata.
    def visitArguments_string_jsonata(self, ctx:ASLParser.Arguments_string_jsonataContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#output_decl.
    def visitOutput_decl(self, ctx:ASLParser.Output_declContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#jsonata_template_value_object.
    def visitJsonata_template_value_object(self, ctx:ASLParser.Jsonata_template_value_objectContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#jsonata_template_binding.
    def visitJsonata_template_binding(self, ctx:ASLParser.Jsonata_template_bindingContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#jsonata_template_value.
    def visitJsonata_template_value(self, ctx:ASLParser.Jsonata_template_valueContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#jsonata_template_value_array.
    def visitJsonata_template_value_array(self, ctx:ASLParser.Jsonata_template_value_arrayContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#jsonata_template_value_terminal_float.
    def visitJsonata_template_value_terminal_float(self, ctx:ASLParser.Jsonata_template_value_terminal_floatContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#jsonata_template_value_terminal_int.
    def visitJsonata_template_value_terminal_int(self, ctx:ASLParser.Jsonata_template_value_terminal_intContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#jsonata_template_value_terminal_bool.
    def visitJsonata_template_value_terminal_bool(self, ctx:ASLParser.Jsonata_template_value_terminal_boolContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#jsonata_template_value_terminal_null.
    def visitJsonata_template_value_terminal_null(self, ctx:ASLParser.Jsonata_template_value_terminal_nullContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#jsonata_template_value_terminal_string_jsonata.
    def visitJsonata_template_value_terminal_string_jsonata(self, ctx:ASLParser.Jsonata_template_value_terminal_string_jsonataContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#jsonata_template_value_terminal_string_literal.
    def visitJsonata_template_value_terminal_string_literal(self, ctx:ASLParser.Jsonata_template_value_terminal_string_literalContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#result_selector_decl.
    def visitResult_selector_decl(self, ctx:ASLParser.Result_selector_declContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#state_type.
    def visitState_type(self, ctx:ASLParser.State_typeContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#choices_decl.
    def visitChoices_decl(self, ctx:ASLParser.Choices_declContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#choice_rule_comparison_variable.
    def visitChoice_rule_comparison_variable(self, ctx:ASLParser.Choice_rule_comparison_variableContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#choice_rule_comparison_composite.
    def visitChoice_rule_comparison_composite(self, ctx:ASLParser.Choice_rule_comparison_compositeContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#comparison_variable_stmt.
    def visitComparison_variable_stmt(self, ctx:ASLParser.Comparison_variable_stmtContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#comparison_composite_stmt.
    def visitComparison_composite_stmt(self, ctx:ASLParser.Comparison_composite_stmtContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#comparison_composite.
    def visitComparison_composite(self, ctx:ASLParser.Comparison_compositeContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#variable_decl.
    def visitVariable_decl(self, ctx:ASLParser.Variable_declContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#condition_lit.
    def visitCondition_lit(self, ctx:ASLParser.Condition_litContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#condition_string_jsonata.
    def visitCondition_string_jsonata(self, ctx:ASLParser.Condition_string_jsonataContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#comparison_func_string_variable_sample.
    def visitComparison_func_string_variable_sample(self, ctx:ASLParser.Comparison_func_string_variable_sampleContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#comparison_func_value.
    def visitComparison_func_value(self, ctx:ASLParser.Comparison_func_valueContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#branches_decl.
    def visitBranches_decl(self, ctx:ASLParser.Branches_declContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#item_processor_decl.
    def visitItem_processor_decl(self, ctx:ASLParser.Item_processor_declContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#item_processor_item.
    def visitItem_processor_item(self, ctx:ASLParser.Item_processor_itemContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#processor_config_decl.
    def visitProcessor_config_decl(self, ctx:ASLParser.Processor_config_declContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#processor_config_field.
    def visitProcessor_config_field(self, ctx:ASLParser.Processor_config_fieldContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#mode_decl.
    def visitMode_decl(self, ctx:ASLParser.Mode_declContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#mode_type.
    def visitMode_type(self, ctx:ASLParser.Mode_typeContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#execution_decl.
    def visitExecution_decl(self, ctx:ASLParser.Execution_declContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#execution_type.
    def visitExecution_type(self, ctx:ASLParser.Execution_typeContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#iterator_decl.
    def visitIterator_decl(self, ctx:ASLParser.Iterator_declContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#iterator_decl_item.
    def visitIterator_decl_item(self, ctx:ASLParser.Iterator_decl_itemContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#item_selector_decl.
    def visitItem_selector_decl(self, ctx:ASLParser.Item_selector_declContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#item_reader_decl.
    def visitItem_reader_decl(self, ctx:ASLParser.Item_reader_declContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#items_reader_field.
    def visitItems_reader_field(self, ctx:ASLParser.Items_reader_fieldContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#reader_config_decl.
    def visitReader_config_decl(self, ctx:ASLParser.Reader_config_declContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#reader_config_field.
    def visitReader_config_field(self, ctx:ASLParser.Reader_config_fieldContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#input_type_decl.
    def visitInput_type_decl(self, ctx:ASLParser.Input_type_declContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#csv_header_location_decl.
    def visitCsv_header_location_decl(self, ctx:ASLParser.Csv_header_location_declContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#csv_headers_decl.
    def visitCsv_headers_decl(self, ctx:ASLParser.Csv_headers_declContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#max_items_string_jsonata.
    def visitMax_items_string_jsonata(self, ctx:ASLParser.Max_items_string_jsonataContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#max_items_int.
    def visitMax_items_int(self, ctx:ASLParser.Max_items_intContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#max_items_path.
    def visitMax_items_path(self, ctx:ASLParser.Max_items_pathContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#tolerated_failure_count_string_jsonata.
    def visitTolerated_failure_count_string_jsonata(self, ctx:ASLParser.Tolerated_failure_count_string_jsonataContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#tolerated_failure_count_int.
    def visitTolerated_failure_count_int(self, ctx:ASLParser.Tolerated_failure_count_intContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#tolerated_failure_count_path.
    def visitTolerated_failure_count_path(self, ctx:ASLParser.Tolerated_failure_count_pathContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#tolerated_failure_percentage_string_jsonata.
    def visitTolerated_failure_percentage_string_jsonata(self, ctx:ASLParser.Tolerated_failure_percentage_string_jsonataContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#tolerated_failure_percentage_number.
    def visitTolerated_failure_percentage_number(self, ctx:ASLParser.Tolerated_failure_percentage_numberContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#tolerated_failure_percentage_path.
    def visitTolerated_failure_percentage_path(self, ctx:ASLParser.Tolerated_failure_percentage_pathContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#label_decl.
    def visitLabel_decl(self, ctx:ASLParser.Label_declContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#result_writer_decl.
    def visitResult_writer_decl(self, ctx:ASLParser.Result_writer_declContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#result_writer_field.
    def visitResult_writer_field(self, ctx:ASLParser.Result_writer_fieldContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#retry_decl.
    def visitRetry_decl(self, ctx:ASLParser.Retry_declContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#retrier_decl.
    def visitRetrier_decl(self, ctx:ASLParser.Retrier_declContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#retrier_stmt.
    def visitRetrier_stmt(self, ctx:ASLParser.Retrier_stmtContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#error_equals_decl.
    def visitError_equals_decl(self, ctx:ASLParser.Error_equals_declContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#interval_seconds_decl.
    def visitInterval_seconds_decl(self, ctx:ASLParser.Interval_seconds_declContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#max_attempts_decl.
    def visitMax_attempts_decl(self, ctx:ASLParser.Max_attempts_declContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#backoff_rate_decl.
    def visitBackoff_rate_decl(self, ctx:ASLParser.Backoff_rate_declContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#max_delay_seconds_decl.
    def visitMax_delay_seconds_decl(self, ctx:ASLParser.Max_delay_seconds_declContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#jitter_strategy_decl.
    def visitJitter_strategy_decl(self, ctx:ASLParser.Jitter_strategy_declContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#catch_decl.
    def visitCatch_decl(self, ctx:ASLParser.Catch_declContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#catcher_decl.
    def visitCatcher_decl(self, ctx:ASLParser.Catcher_declContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#catcher_stmt.
    def visitCatcher_stmt(self, ctx:ASLParser.Catcher_stmtContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#comparison_op.
    def visitComparison_op(self, ctx:ASLParser.Comparison_opContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#choice_operator.
    def visitChoice_operator(self, ctx:ASLParser.Choice_operatorContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#states_error_name.
    def visitStates_error_name(self, ctx:ASLParser.States_error_nameContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#error_name.
    def visitError_name(self, ctx:ASLParser.Error_nameContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#json_obj_decl.
    def visitJson_obj_decl(self, ctx:ASLParser.Json_obj_declContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#json_binding.
    def visitJson_binding(self, ctx:ASLParser.Json_bindingContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#json_arr_decl.
    def visitJson_arr_decl(self, ctx:ASLParser.Json_arr_declContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#json_value_decl.
    def visitJson_value_decl(self, ctx:ASLParser.Json_value_declContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#string_sampler.
    def visitString_sampler(self, ctx:ASLParser.String_samplerContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#string_expression_simple.
    def visitString_expression_simple(self, ctx:ASLParser.String_expression_simpleContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#string_expression.
    def visitString_expression(self, ctx:ASLParser.String_expressionContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#string_jsonpath.
    def visitString_jsonpath(self, ctx:ASLParser.String_jsonpathContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#string_context_path.
    def visitString_context_path(self, ctx:ASLParser.String_context_pathContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#string_variable_sample.
    def visitString_variable_sample(self, ctx:ASLParser.String_variable_sampleContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#string_intrinsic_function.
    def visitString_intrinsic_function(self, ctx:ASLParser.String_intrinsic_functionContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#string_jsonata.
    def visitString_jsonata(self, ctx:ASLParser.String_jsonataContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#string_literal.
    def visitString_literal(self, ctx:ASLParser.String_literalContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ASLParser#soft_string_keyword.
    def visitSoft_string_keyword(self, ctx:ASLParser.Soft_string_keywordContext):
        return self.visitChildren(ctx)



del ASLParser