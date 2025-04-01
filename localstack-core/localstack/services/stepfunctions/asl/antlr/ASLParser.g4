// $antlr-format alignTrailingComments true, columnLimit 150, maxEmptyLinesToKeep 1, reflowComments false, useTab false
// $antlr-format allowShortRulesOnASingleLine true, allowShortBlocksOnASingleLine true, minEmptyLines 0, alignSemicolons ownLine
// $antlr-format alignColons trailing, singleLineOverrulesHangingColon true, alignLexerCommands true, alignLabels true, alignTrailers true

parser grammar ASLParser;

options {
    tokenVocab = ASLLexer;
}

state_machine: program_decl EOF;

program_decl: LBRACE top_layer_stmt (COMMA top_layer_stmt)* RBRACE;

top_layer_stmt:
    comment_decl
    | version_decl
    | query_language_decl
    | startat_decl
    | states_decl
    | timeout_seconds_decl
;

startat_decl: STARTAT COLON string_literal;

comment_decl: COMMENT COLON string_literal;

version_decl: VERSION COLON string_literal;

query_language_decl: QUERYLANGUAGE COLON (JSONPATH | JSONATA);

state_stmt:
    comment_decl
    | query_language_decl
    | type_decl
    | input_path_decl
    | resource_decl
    | next_decl
    | result_decl
    | result_path_decl
    | output_path_decl
    | end_decl
    | default_decl
    | choices_decl
    | error_decl
    | cause_decl
    | seconds_decl
    | timestamp_decl
    | items_decl
    | items_path_decl
    | item_processor_decl
    | iterator_decl
    | item_selector_decl
    | item_reader_decl
    | max_concurrency_decl
    | timeout_seconds_decl
    | heartbeat_seconds_decl
    | branches_decl
    | parameters_decl
    | retry_decl
    | catch_decl
    | result_selector_decl
    | tolerated_failure_count_decl
    | tolerated_failure_percentage_decl
    | label_decl
    | result_writer_decl
    | assign_decl
    | arguments_decl
    | output_decl
    | credentials_decl
;

states_decl: STATES COLON LBRACE state_decl (COMMA state_decl)* RBRACE;

state_decl: string_literal COLON state_decl_body;

state_decl_body: LBRACE state_stmt (COMMA state_stmt)* RBRACE;

type_decl: TYPE COLON state_type;

next_decl: NEXT COLON string_literal;

resource_decl: RESOURCE COLON string_literal;

input_path_decl: INPUTPATH COLON (NULL | string_sampler);

result_decl: RESULT COLON json_value_decl;

result_path_decl: RESULTPATH COLON (NULL | string_jsonpath);

output_path_decl: OUTPUTPATH COLON (NULL | string_sampler);

end_decl: END COLON (TRUE | FALSE);

default_decl: DEFAULT COLON string_literal;

error_decl:
    ERROR COLON (string_jsonata | string_literal) # error
    | ERRORPATH COLON string_expression_simple    # error_path
;

cause_decl:
    CAUSE COLON (string_jsonata | string_literal) # cause
    | CAUSEPATH COLON string_expression_simple    # cause_path
;

seconds_decl:
    SECONDS COLON string_jsonata       # seconds_jsonata
    | SECONDS COLON INT                # seconds_int
    | SECONDSPATH COLON string_sampler # seconds_path
;

timestamp_decl:
    TIMESTAMP COLON (string_jsonata | string_literal) # timestamp
    | TIMESTAMPPATH COLON string_sampler              # timestamp_path
;

items_decl:
    ITEMS COLON jsonata_template_value_array # items_array
    | ITEMS COLON string_jsonata             # items_jsonata
;

items_path_decl: ITEMSPATH COLON string_sampler;

max_concurrency_decl:
    MAXCONCURRENCY COLON string_jsonata       # max_concurrency_jsonata
    | MAXCONCURRENCY COLON INT                # max_concurrency_int
    | MAXCONCURRENCYPATH COLON string_sampler # max_concurrency_path
;

parameters_decl: PARAMETERS COLON payload_tmpl_decl;

credentials_decl: CREDENTIALS COLON LBRACE role_arn_decl RBRACE;

role_arn_decl:
    ROLEARN COLON (string_jsonata | string_literal) # role_arn
    | ROLEARNPATH COLON string_expression_simple    # role_path
;

timeout_seconds_decl:
    TIMEOUTSECONDS COLON string_jsonata       # timeout_seconds_jsonata
    | TIMEOUTSECONDS COLON INT                # timeout_seconds_int
    | TIMEOUTSECONDSPATH COLON string_sampler # timeout_seconds_path
;

heartbeat_seconds_decl:
    HEARTBEATSECONDS COLON string_jsonata       # heartbeat_seconds_jsonata
    | HEARTBEATSECONDS COLON INT                # heartbeat_seconds_int
    | HEARTBEATSECONDSPATH COLON string_sampler # heartbeat_seconds_path
;

payload_tmpl_decl: LBRACE payload_binding (COMMA payload_binding)* RBRACE | LBRACE RBRACE;

payload_binding:
    STRINGDOLLAR COLON string_expression_simple # payload_binding_sample
    | string_literal COLON payload_value_decl   # payload_binding_value
;

payload_arr_decl: LBRACK payload_value_decl (COMMA payload_value_decl)* RBRACK | LBRACK RBRACK;

payload_value_decl: payload_arr_decl | payload_tmpl_decl | payload_value_lit;

payload_value_lit:
    NUMBER           # payload_value_float
    | INT            # payload_value_int
    | (TRUE | FALSE) # payload_value_bool
    | NULL           # payload_value_null
    | string_literal # payload_value_str
;

assign_decl: ASSIGN COLON assign_decl_body;

assign_decl_body: LBRACE RBRACE | LBRACE assign_decl_binding (COMMA assign_decl_binding)* RBRACE;

assign_decl_binding: assign_template_binding;

assign_template_value_object:
    LBRACE RBRACE
    | LBRACE assign_template_binding (COMMA assign_template_binding)* RBRACE
;

assign_template_binding:
    STRINGDOLLAR COLON string_expression_simple  # assign_template_binding_string_expression_simple
    | string_literal COLON assign_template_value # assign_template_binding_value
;

assign_template_value:
    assign_template_value_object
    | assign_template_value_array
    | assign_template_value_terminal
;

assign_template_value_array:
    LBRACK RBRACK
    | LBRACK assign_template_value (COMMA assign_template_value)* RBRACK
;

assign_template_value_terminal:
    NUMBER           # assign_template_value_terminal_float
    | INT            # assign_template_value_terminal_int
    | (TRUE | FALSE) # assign_template_value_terminal_bool
    | NULL           # assign_template_value_terminal_null
    | string_jsonata # assign_template_value_terminal_string_jsonata
    | string_literal # assign_template_value_terminal_string_literal
;

arguments_decl:
    ARGUMENTS COLON jsonata_template_value_object # arguments_jsonata_template_value_object
    | ARGUMENTS COLON string_jsonata              # arguments_string_jsonata
;

output_decl: OUTPUT COLON jsonata_template_value;

jsonata_template_value_object:
    LBRACE RBRACE
    | LBRACE jsonata_template_binding (COMMA jsonata_template_binding)* RBRACE
;

jsonata_template_binding: string_literal COLON jsonata_template_value;

jsonata_template_value:
    jsonata_template_value_object
    | jsonata_template_value_array
    | jsonata_template_value_terminal
;

jsonata_template_value_array:
    LBRACK RBRACK
    | LBRACK jsonata_template_value (COMMA jsonata_template_value)* RBRACK
;

jsonata_template_value_terminal:
    NUMBER           # jsonata_template_value_terminal_float
    | INT            # jsonata_template_value_terminal_int
    | (TRUE | FALSE) # jsonata_template_value_terminal_bool
    | NULL           # jsonata_template_value_terminal_null
    | string_jsonata # jsonata_template_value_terminal_string_jsonata
    | string_literal # jsonata_template_value_terminal_string_literal
;

result_selector_decl: RESULTSELECTOR COLON payload_tmpl_decl;

state_type: TASK | PASS | CHOICE | FAIL | SUCCEED | WAIT | MAP | PARALLEL;

choices_decl: CHOICES COLON LBRACK choice_rule (COMMA choice_rule)* RBRACK;

choice_rule:
    LBRACE comparison_variable_stmt (COMMA comparison_variable_stmt)+ RBRACE     # choice_rule_comparison_variable
    | LBRACE comparison_composite_stmt (COMMA comparison_composite_stmt)* RBRACE # choice_rule_comparison_composite
;

comparison_variable_stmt:
    variable_decl
    | comparison_func
    | next_decl
    | assign_decl
    | output_decl
    | comment_decl
;

comparison_composite_stmt: comparison_composite | next_decl | assign_decl | comment_decl;

comparison_composite:
    choice_operator COLON (choice_rule | LBRACK choice_rule (COMMA choice_rule)* RBRACK)
; // TODO: this allows for Next definitions in nested choice_rules, is this supported at parse time?

variable_decl: VARIABLE COLON string_sampler;

comparison_func:
    CONDITION COLON (TRUE | FALSE)               # condition_lit
    | CONDITION COLON string_jsonata             # condition_string_jsonata
    | comparison_op COLON string_variable_sample # comparison_func_string_variable_sample
    | comparison_op COLON json_value_decl        # comparison_func_value
;

branches_decl: BRANCHES COLON LBRACK program_decl (COMMA program_decl)* RBRACK;

item_processor_decl:
    ITEMPROCESSOR COLON LBRACE item_processor_item (COMMA item_processor_item)* RBRACE
;

item_processor_item: processor_config_decl | startat_decl | states_decl | comment_decl;

processor_config_decl:
    PROCESSORCONFIG COLON LBRACE processor_config_field (COMMA processor_config_field)* RBRACE
;

processor_config_field: mode_decl | execution_decl;

mode_decl: MODE COLON mode_type;

mode_type: INLINE | DISTRIBUTED;

execution_decl: EXECUTIONTYPE COLON execution_type;

execution_type: STANDARD;

iterator_decl: ITERATOR COLON LBRACE iterator_decl_item (COMMA iterator_decl_item)* RBRACE;

iterator_decl_item: startat_decl | states_decl | comment_decl | processor_config_decl;

item_selector_decl: ITEMSELECTOR COLON assign_template_value_object;

item_reader_decl: ITEMREADER COLON LBRACE items_reader_field (COMMA items_reader_field)* RBRACE;

items_reader_field: resource_decl | reader_config_decl | parameters_decl | arguments_decl;

reader_config_decl:
    READERCONFIG COLON LBRACE reader_config_field (COMMA reader_config_field)* RBRACE
;

reader_config_field:
    input_type_decl
    | csv_header_location_decl
    | csv_headers_decl
    | max_items_decl
;

input_type_decl: INPUTTYPE COLON string_literal;

csv_header_location_decl: CSVHEADERLOCATION COLON string_literal;

csv_headers_decl:
    CSVHEADERS COLON LBRACK string_literal (COMMA string_literal)* RBRACK
; // TODO: are empty "CSVHeaders" list values supported?

max_items_decl:
    MAXITEMS COLON string_jsonata       # max_items_string_jsonata
    | MAXITEMS COLON INT                # max_items_int
    | MAXITEMSPATH COLON string_sampler # max_items_path
;

tolerated_failure_count_decl:
    TOLERATEDFAILURECOUNT COLON string_jsonata       # tolerated_failure_count_string_jsonata
    | TOLERATEDFAILURECOUNT COLON INT                # tolerated_failure_count_int
    | TOLERATEDFAILURECOUNTPATH COLON string_sampler # tolerated_failure_count_path
;

tolerated_failure_percentage_decl:
    TOLERATEDFAILUREPERCENTAGE COLON string_jsonata       # tolerated_failure_percentage_string_jsonata
    | TOLERATEDFAILUREPERCENTAGE COLON NUMBER             # tolerated_failure_percentage_number
    | TOLERATEDFAILUREPERCENTAGEPATH COLON string_sampler # tolerated_failure_percentage_path
;

label_decl: LABEL COLON string_literal;

result_writer_decl:
    RESULTWRITER COLON LBRACE result_writer_field (COMMA result_writer_field)* RBRACE
;

result_writer_field: resource_decl | parameters_decl;

retry_decl: RETRY COLON LBRACK (retrier_decl (COMMA retrier_decl)*)? RBRACK;

retrier_decl: LBRACE retrier_stmt (COMMA retrier_stmt)* RBRACE;

retrier_stmt:
    error_equals_decl
    | interval_seconds_decl
    | max_attempts_decl
    | backoff_rate_decl
    | max_delay_seconds_decl
    | jitter_strategy_decl
    | comment_decl
;

error_equals_decl: ERROREQUALS COLON LBRACK error_name (COMMA error_name)* RBRACK;

interval_seconds_decl: INTERVALSECONDS COLON INT;

max_attempts_decl: MAXATTEMPTS COLON INT;

backoff_rate_decl: BACKOFFRATE COLON (INT | NUMBER);

max_delay_seconds_decl: MAXDELAYSECONDS COLON INT;

jitter_strategy_decl: JITTERSTRATEGY COLON (FULL | NONE);

catch_decl: CATCH COLON LBRACK (catcher_decl (COMMA catcher_decl)*)? RBRACK;

catcher_decl: LBRACE catcher_stmt (COMMA catcher_stmt)* RBRACE;

catcher_stmt:
    error_equals_decl
    | result_path_decl
    | next_decl
    | assign_decl
    | output_decl
    | comment_decl
;

comparison_op:
    BOOLEANEQUALS
    | BOOLEANQUALSPATH
    | ISBOOLEAN
    | ISNULL
    | ISNUMERIC
    | ISPRESENT
    | ISSTRING
    | ISTIMESTAMP
    | NUMERICEQUALS
    | NUMERICEQUALSPATH
    | NUMERICGREATERTHAN
    | NUMERICGREATERTHANPATH
    | NUMERICGREATERTHANEQUALS
    | NUMERICGREATERTHANEQUALSPATH
    | NUMERICLESSTHAN
    | NUMERICLESSTHANPATH
    | NUMERICLESSTHANEQUALS
    | NUMERICLESSTHANEQUALSPATH
    | STRINGEQUALS
    | STRINGEQUALSPATH
    | STRINGGREATERTHAN
    | STRINGGREATERTHANPATH
    | STRINGGREATERTHANEQUALS
    | STRINGGREATERTHANEQUALSPATH
    | STRINGLESSTHAN
    | STRINGLESSTHANPATH
    | STRINGLESSTHANEQUALS
    | STRINGLESSTHANEQUALSPATH
    | STRINGMATCHES
    | TIMESTAMPEQUALS
    | TIMESTAMPEQUALSPATH
    | TIMESTAMPGREATERTHAN
    | TIMESTAMPGREATERTHANPATH
    | TIMESTAMPGREATERTHANEQUALS
    | TIMESTAMPGREATERTHANEQUALSPATH
    | TIMESTAMPLESSTHAN
    | TIMESTAMPLESSTHANPATH
    | TIMESTAMPLESSTHANEQUALS
    | TIMESTAMPLESSTHANEQUALSPATH
;

choice_operator: NOT | AND | OR;

states_error_name:
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
    | ERRORNAMEStatesRuntime
    | ERRORNAMEStatesQueryEvaluationError
;

error_name: states_error_name | string_literal;

json_obj_decl: LBRACE json_binding (COMMA json_binding)* RBRACE | LBRACE RBRACE;

json_binding: string_literal COLON json_value_decl;

json_arr_decl: LBRACK json_value_decl (COMMA json_value_decl)* RBRACK | LBRACK RBRACK;

json_value_decl:
    NUMBER
    | INT
    | TRUE
    | FALSE
    | NULL
    | json_binding
    | json_arr_decl
    | json_obj_decl
    | string_literal
;

string_sampler           : string_jsonpath | string_context_path | string_variable_sample;
string_expression_simple : string_sampler | string_intrinsic_function;
string_expression        : string_expression_simple | string_jsonata;

string_jsonpath           : STRINGPATH;
string_context_path       : STRINGPATHCONTEXTOBJ;
string_variable_sample    : STRINGVAR;
string_intrinsic_function : STRINGINTRINSICFUNC;
string_jsonata            : STRINGJSONATA;
string_literal:
    STRING
    | STRINGDOLLAR
    | soft_string_keyword
    | comparison_op
    | choice_operator
    | states_error_name
    | string_expression
;

soft_string_keyword:
    QUERYLANGUAGE
    | ASSIGN
    | ARGUMENTS
    | OUTPUT
    | COMMENT
    | STATES
    | STARTAT
    | NEXTSTATE
    | TYPE
    | TASK
    | CHOICE
    | FAIL
    | SUCCEED
    | PASS
    | WAIT
    | PARALLEL
    | MAP
    | CHOICES
    | CONDITION
    | VARIABLE
    | DEFAULT
    | BRANCHES
    | SECONDSPATH
    | SECONDS
    | TIMESTAMPPATH
    | TIMESTAMP
    | TIMEOUTSECONDS
    | TIMEOUTSECONDSPATH
    | HEARTBEATSECONDS
    | HEARTBEATSECONDSPATH
    | PROCESSORCONFIG
    | MODE
    | INLINE
    | DISTRIBUTED
    | EXECUTIONTYPE
    | STANDARD
    | ITEMS
    | ITEMPROCESSOR
    | ITERATOR
    | ITEMSELECTOR
    | MAXCONCURRENCY
    | MAXCONCURRENCYPATH
    | RESOURCE
    | INPUTPATH
    | OUTPUTPATH
    | ITEMSPATH
    | RESULTPATH
    | RESULT
    | PARAMETERS
    | CREDENTIALS
    | ROLEARN
    | ROLEARNPATH
    | RESULTSELECTOR
    | ITEMREADER
    | READERCONFIG
    | INPUTTYPE
    | CSVHEADERLOCATION
    | CSVHEADERS
    | MAXITEMS
    | MAXITEMSPATH
    | TOLERATEDFAILURECOUNT
    | TOLERATEDFAILURECOUNTPATH
    | TOLERATEDFAILUREPERCENTAGE
    | TOLERATEDFAILUREPERCENTAGEPATH
    | LABEL
    | RESULTWRITER
    | NEXT
    | END
    | CAUSE
    | ERROR
    | RETRY
    | ERROREQUALS
    | INTERVALSECONDS
    | MAXATTEMPTS
    | BACKOFFRATE
    | MAXDELAYSECONDS
    | JITTERSTRATEGY
    | FULL
    | NONE
    | CATCH
    | VERSION
;