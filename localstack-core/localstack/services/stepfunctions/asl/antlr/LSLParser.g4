// $antlr-format alignTrailingComments true, columnLimit 150, maxEmptyLinesToKeep 1, reflowComments false, useTab false
// $antlr-format allowShortRulesOnASingleLine true, allowShortBlocksOnASingleLine true, minEmptyLines 0, alignSemicolons ownLine
// $antlr-format alignColons trailing, singleLineOverrulesHangingColon true, alignLexerCommands true, alignLabels true, alignTrailers true

parser grammar LSLParser;

options {
    tokenVocab = LSLLexer;
}

state_machine: (state_declaration | var_assign | state_call)+ EOF;

state_declaration:
    IDEN parameter_list EQUALS state
;

state_call:
    IDEN args_assign_list  # state_call_template
    | IDEN AS state        # state_call_named
    | state                # state_call_anonymous
    ;

state:
    service_name COLON IDEN task_where  # state_task
    | FAIL fail_where                   # state_fail
    | SUCCEED succeed_where             # state_succeed
;

service_name: LAMBDA;

task_where: WHERE arguments? catch_block?;
fail_where: WHERE error cause?;
succeed_where: WHERE output_block;

arguments: ARGUMENTS json_value;
catch_block: CATCH LBRACE catch_case (catch_case)* RBRACE;
catch_case: error_name ARROW state_call;

parameter_list:
    LPAREN IDEN? (COMMA IDEN)* RPAREN
;

args_assign_list:
    LPAREN args_assign (COMMA args_assign)* RPAREN
;
args_assign: IDEN EQUALS json_value;

error: ERROR string_or_jsonata;
cause: CAUSE string_or_jsonata;

output_block: OUTPUT json_value;

var_assign:
    IDEN EQUALS state_call    # var_assign_state_call
    | IDEN EQUALS json_value  # var_assign_json_value
;

json_value: json_object | json_arr | json_value_lit;
json_object: LBRACE json_binding (COMMA json_binding)* RBRACE | LBRACE RBRACE;
json_binding: (STRING | IDEN) COLON json_value;
json_arr: LBRACK json_value (COMMA json_value)* RBRACK | LBRACK RBRACK;
json_value_lit:
    NUMBER            # json_value_float
    | INT             # json_value_int
    | (TRUE | FALSE)  # json_value_bool
    | NULL            # json_value_null
    | STRING          # json_value_str
    | JSONATA         # json_value_jsonata
;

string_or_jsonata:
    STRING     # string_or_jsonata_string
    | JSONATA  # string_or_jsonata_jsonata
;

error_name:
    ERRORNAMEStatesALL
    | ERRORNAMEStatesDataLimitExceeded
    | ERRORNAMEStatesHeartbeatTimeout
    | ERRORNAMEStatesTimeout
    | ERRORNAMEStatesTaskFailed
    | ERRORNAMEStatesPermissions
    | ERRORNAMEStatesResultPathMatchFailure
    | ERRORNAMEStatesParameterPathFailure
    | ERRORNAMEStatesBranchFailed
    | ERRORNAMEStatesNoChoiceMatched
    | ERRORNAMEStatesIntrinsicFailure
    | ERRORNAMEStatesExceedToleratedFailureThreshold
    | ERRORNAMEStatesItemReaderFailed
    | ERRORNAMEStatesResultWriterFailed
    | ERRORNAMEStatesQueryEvaluationError
    | STRING
;
