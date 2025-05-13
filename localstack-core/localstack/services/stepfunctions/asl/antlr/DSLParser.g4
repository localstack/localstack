// $antlr-format alignTrailingComments true, columnLimit 150, maxEmptyLinesToKeep 1, reflowComments false, useTab false
// $antlr-format allowShortRulesOnASingleLine true, allowShortBlocksOnASingleLine true, minEmptyLines 0, alignSemicolons ownLine
// $antlr-format alignColons trailing, singleLineOverrulesHangingColon true, alignLexerCommands true, alignLabels true, alignTrailers true

parser grammar DSLParser;

options {
    tokenVocab = DSLLexer;
}

workflow: state_declaration* state_call+ EOF;

state_declaration:
    IDEN (LPAREN IDEN (COMMA IDEN)* RPAREN)? EQUALS state
;

state:
    task_state
    | fail_state
;

task_state:
    service_name COLON IDEN task_state_with;

service_name: LAMBDA;

task_state_with:
    WITH parameters? catch_?
;

parameters: PARAMETERS json_value;
catch_: CATCH LBRACE catch_case (catch_case)* RBRACE;
catch_case:
    STRING ARROW state #catch_case_state
    | STRING ARROW state_call #catch_case_call
;

state_call:
    IDEN LPAREN (argument_assignment (COMMA argument_assignment)*)? RPAREN
    | IDEN AS state;

argument_assignment:
    IDEN EQUALS json_value
;


fail_state: FAIL WITH error cause?;
error: ERROR STRING;
cause: CAUSE STRING;


json_object: LBRACE json_binding (COMMA json_binding)* RBRACE | LBRACE RBRACE;

json_binding:
    | STRING COLON json_value
;

json_arr: LBRACK json_value (COMMA json_value)* RBRACK | LBRACK RBRACK;

json_value: json_object | json_arr | json_value_lit;

json_value_lit:
    NUMBER           # json_value_float
    | INT            # json_value_int
    | (TRUE | FALSE) # json_value_bool
    | NULL           # json_value_null
    | STRING         # json_value_str
    | JSONATA        # json_value_jsonata
;
