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

startat_decl: STARTAT COLON keyword_or_string;

comment_decl: COMMENT COLON keyword_or_string;

version_decl: VERSION COLON keyword_or_string;

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
    | error_path_decl
    | cause_decl
    | cause_path_decl
    | seconds_decl
    | seconds_path_decl
    | timestamp_decl
    | timestamp_path_decl
    | items_decl
    | items_path_decl
    | item_processor_decl
    | iterator_decl
    | item_selector_decl
    | item_reader_decl
    | max_concurrency_decl
    | max_concurrency_path_decl
    | timeout_seconds_decl
    | timeout_seconds_path_decl
    | heartbeat_seconds_decl
    | heartbeat_seconds_path_decl
    | branches_decl
    | parameters_decl
    | retry_decl
    | catch_decl
    | result_selector_decl
    | tolerated_failure_count_decl
    | tolerated_failure_count_path_decl
    | tolerated_failure_percentage_decl
    | tolerated_failure_percentage_path_decl
    | label_decl
    | result_writer_decl
    | assign_decl
    | arguments_decl
    | output_decl
    | credentials_decl
;

states_decl: STATES COLON LBRACE state_decl (COMMA state_decl)* RBRACE;

state_name: keyword_or_string;

// TODO: avoid redefinitions? -> check listener ok?
state_decl: state_name COLON state_decl_body;

state_decl_body: LBRACE state_stmt (COMMA state_stmt)* RBRACE;

type_decl: TYPE COLON state_type;

next_decl: NEXT COLON keyword_or_string;

resource_decl: RESOURCE COLON keyword_or_string;

input_path_decl:
    INPUTPATH COLON variable_sample              # input_path_decl_var
    | INPUTPATH COLON STRINGPATHCONTEXTOBJ       # input_path_decl_path_context_object
    | INPUTPATH COLON (NULL | keyword_or_string) # input_path_decl_path
;

result_decl: RESULT COLON json_value_decl;

result_path_decl: RESULTPATH COLON (NULL | keyword_or_string);

output_path_decl:
    OUTPUTPATH COLON variable_sample              # output_path_decl_var
    | OUTPUTPATH COLON STRINGPATHCONTEXTOBJ       # output_path_decl_path_context_object
    | OUTPUTPATH COLON (NULL | keyword_or_string) # output_path_decl_path
;

end_decl: END COLON (TRUE | FALSE);

default_decl: DEFAULT COLON keyword_or_string;

error_decl:
    ERROR COLON STRINGJSONATA       # error_jsonata
    | ERROR COLON keyword_or_string # error_string
;

error_path_decl:
    ERRORPATH COLON variable_sample       # error_path_decl_var
    | ERRORPATH COLON STRINGPATH          # error_path_decl_path
    | ERRORPATH COLON STRINGINTRINSICFUNC # error_path_decl_intrinsic
;

cause_decl:
    CAUSE COLON STRINGJSONATA       # cause_jsonata
    | CAUSE COLON keyword_or_string # cause_string
;

cause_path_decl:
    CAUSEPATH COLON variable_sample       # cause_path_decl_var
    | CAUSEPATH COLON STRINGPATH          # cause_path_decl_path
    | CAUSEPATH COLON STRINGINTRINSICFUNC # cause_path_decl_intrinsic
;

seconds_decl: SECONDS COLON STRINGJSONATA # seconds_jsonata | SECONDS COLON INT # seconds_int;

seconds_path_decl:
    SECONDSPATH COLON variable_sample     # seconds_path_decl_var
    | SECONDSPATH COLON keyword_or_string # seconds_path_decl_value
;

timestamp_decl:
    TIMESTAMP COLON STRINGJSONATA       # timestamp_jsonata
    | TIMESTAMP COLON keyword_or_string # timestamp_string
;

timestamp_path_decl:
    TIMESTAMPPATH COLON variable_sample     # timestamp_path_decl_var
    | TIMESTAMPPATH COLON keyword_or_string # timestamp_path_decl_value
;

items_decl:
    ITEMS COLON jsonata_template_value_array # items_array
    | ITEMS COLON STRINGJSONATA              # items_jsonata
;

items_path_decl:
    ITEMSPATH COLON STRINGPATHCONTEXTOBJ # items_path_decl_path_context_object
    | ITEMSPATH COLON variable_sample    # items_path_decl_path_var
    | ITEMSPATH COLON keyword_or_string  # items_path_decl_path
;

max_concurrency_decl:
    MAXCONCURRENCY COLON STRINGJSONATA # max_concurrency_jsonata
    | MAXCONCURRENCY COLON INT         # max_concurrency_int
;

max_concurrency_path_decl:
    MAXCONCURRENCYPATH COLON variable_sample # max_concurrency_path_var
    | MAXCONCURRENCYPATH COLON STRINGPATH    # max_concurrency_path
;

parameters_decl: PARAMETERS COLON payload_tmpl_decl;

credentials_decl: CREDENTIALS COLON payload_tmpl_decl;

timeout_seconds_decl:
    TIMEOUTSECONDS COLON STRINGJSONATA # timeout_seconds_jsonata
    | TIMEOUTSECONDS COLON INT         # timeout_seconds_int
;

timeout_seconds_path_decl:
    TIMEOUTSECONDSPATH COLON variable_sample # timeout_seconds_path_decl_var
    | TIMEOUTSECONDSPATH COLON STRINGPATH    # timeout_seconds_path_decl_path
;

heartbeat_seconds_decl:
    HEARTBEATSECONDS COLON STRINGJSONATA # heartbeat_seconds_jsonata
    | HEARTBEATSECONDS COLON INT         # heartbeat_seconds_int
;

heartbeat_seconds_path_decl:
    HEARTBEATSECONDSPATH COLON variable_sample # heartbeat_seconds_path_decl_var
    | HEARTBEATSECONDSPATH COLON STRINGPATH    # heartbeat_seconds_path_decl_path
;

variable_sample: STRINGVAR;

payload_tmpl_decl: LBRACE payload_binding (COMMA payload_binding)* RBRACE | LBRACE RBRACE;

payload_binding:
    STRINGDOLLAR COLON STRINGPATH                # payload_binding_path
    | STRINGDOLLAR COLON STRINGPATHCONTEXTOBJ    # payload_binding_path_context_obj
    | STRINGDOLLAR COLON STRINGINTRINSICFUNC     # payload_binding_intrinsic_func
    | STRINGDOLLAR COLON variable_sample         # payload_binding_var
    | keyword_or_string COLON payload_value_decl # payload_binding_value
;

payload_arr_decl: LBRACK payload_value_decl (COMMA payload_value_decl)* RBRACK | LBRACK RBRACK;

payload_value_decl: payload_arr_decl | payload_tmpl_decl | payload_value_lit;

payload_value_lit:
    NUMBER              # payload_value_float
    | INT               # payload_value_int
    | (TRUE | FALSE)    # payload_value_bool
    | NULL              # payload_value_null
    | keyword_or_string # payload_value_str
;

assign_decl: ASSIGN COLON assign_decl_body;

assign_decl_body: LBRACE RBRACE | LBRACE assign_decl_binding (COMMA assign_decl_binding)* RBRACE;

assign_decl_binding: assign_template_binding;

assign_template_value_object:
    LBRACE RBRACE
    | LBRACE assign_template_binding (COMMA assign_template_binding)* RBRACE
;

// TODO: add support for jsonata expression in assign declarations.
assign_template_binding:
    STRINGDOLLAR COLON STRINGPATH             # assign_template_binding_path
    | STRINGDOLLAR COLON STRINGPATHCONTEXTOBJ # assign_template_binding_path_context
    | STRINGDOLLAR COLON variable_sample      # assign_template_binding_var
    | STRINGDOLLAR COLON STRINGINTRINSICFUNC  # assign_template_binding_intrinsic_func
    | STRING COLON assign_template_value      # assign_template_binding_assign_value
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
    NUMBER              # assign_template_value_terminal_float
    | INT               # assign_template_value_terminal_int
    | (TRUE | FALSE)    # assign_template_value_terminal_bool
    | NULL              # assign_template_value_terminal_null
    | STRINGJSONATA     # assign_template_value_terminal_expression
    | keyword_or_string # assign_template_value_terminal_str
;

arguments_decl:
    ARGUMENTS COLON jsonata_template_value_object # arguments_object
    | ARGUMENTS COLON STRINGJSONATA               # arguments_expr
;

output_decl: OUTPUT COLON jsonata_template_value;

jsonata_template_value_object:
    LBRACE RBRACE
    | LBRACE jsonata_template_binding (COMMA jsonata_template_binding)* RBRACE
;

jsonata_template_binding: keyword_or_string COLON jsonata_template_value;

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
    NUMBER              # jsonata_template_value_terminal_float
    | INT               # jsonata_template_value_terminal_int
    | (TRUE | FALSE)    # jsonata_template_value_terminal_bool
    | NULL              # jsonata_template_value_terminal_null
    | STRINGJSONATA     # jsonata_template_value_terminal_expression
    | keyword_or_string # jsonata_template_value_terminal_str
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
    | comment_decl
;

comparison_composite_stmt: comparison_composite | next_decl | assign_decl;

comparison_composite
    // TODO: this allows for Next definitions in nested choice_rules, is this supported at parse time?
    : choice_operator COLON (choice_rule | LBRACK choice_rule (COMMA choice_rule)* RBRACK);

variable_decl:
    VARIABLE COLON STRINGPATH             # variable_decl_path
    | VARIABLE COLON variable_sample      # variable_decl_var
    | VARIABLE COLON STRINGPATHCONTEXTOBJ # variable_decl_path_context_object
;

comparison_func:
    CONDITION COLON (TRUE | FALSE)        # condition_lit
    | CONDITION COLON STRINGJSONATA       # condition_expr
    | comparison_op COLON variable_sample # comparison_func_var
    | comparison_op COLON json_value_decl # comparison_func_value
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

item_selector_decl: ITEMSELECTOR COLON payload_tmpl_decl;

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
    | max_items_path_decl
;

input_type_decl: INPUTTYPE COLON keyword_or_string;

csv_header_location_decl: CSVHEADERLOCATION COLON keyword_or_string;

csv_headers_decl // TODO: are empty "CSVHeaders" list values supported?
    : CSVHEADERS COLON LBRACK keyword_or_string (COMMA keyword_or_string)* RBRACK;

max_items_decl:
    MAXITEMS COLON STRINGJSONATA # max_items_jsonata
    | MAXITEMS COLON INT         # max_items_int
;

max_items_path_decl:
    MAXITEMSPATH COLON variable_sample # max_items_path_var
    | MAXITEMSPATH COLON STRINGPATH    # max_items_path
;

tolerated_failure_count_decl:
    TOLERATEDFAILURECOUNT COLON STRINGJSONATA # tolerated_failure_count_jsonata
    | TOLERATEDFAILURECOUNT COLON INT         # tolerated_failure_count_int
;

tolerated_failure_count_path_decl:
    TOLERATEDFAILURECOUNTPATH COLON variable_sample # tolerated_failure_count_path_var
    | TOLERATEDFAILURECOUNTPATH COLON STRINGPATH    # tolerated_failure_count_path
;

tolerated_failure_percentage_decl:
    TOLERATEDFAILUREPERCENTAGE COLON STRINGJSONATA # tolerated_failure_percentage_jsonata
    | TOLERATEDFAILUREPERCENTAGE COLON NUMBER      # tolerated_failure_percentage_number
;

tolerated_failure_percentage_path_decl:
    TOLERATEDFAILUREPERCENTAGEPATH COLON variable_sample # tolerated_failure_percentage_path_var
    | TOLERATEDFAILUREPERCENTAGEPATH COLON STRINGPATH    # tolerated_failure_percentage_path
;

label_decl: LABEL COLON keyword_or_string;

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

error_name: states_error_name | keyword_or_string;

json_obj_decl: LBRACE json_binding (COMMA json_binding)* RBRACE | LBRACE RBRACE;

json_binding: keyword_or_string COLON json_value_decl;

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
    | keyword_or_string
;

keyword_or_string:
    STRINGDOLLAR
    | STRINGINTRINSICFUNC
    | STRINGVAR
    | STRINGPATHCONTEXTOBJ
    | STRINGPATH
    | STRINGJSONATA
    | STRING
    //
    | QUERYLANGUAGE
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
    | AND
    | BOOLEANEQUALS
    | BOOLEANQUALSPATH
    | ISBOOLEAN
    | ISNULL
    | ISNUMERIC
    | ISPRESENT
    | ISSTRING
    | ISTIMESTAMP
    | NOT
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
    | OR
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
    | ERRORNAMEStatesALL
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