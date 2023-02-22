parser grammar ASLParser;

options {
    tokenVocab=ASLLexer;
}

program_decl
    : LBRACE
      top_layer_stmt (COMMA top_layer_stmt)*
      RBRACE
    ;

top_layer_stmt
    : comment_decl
    | startat_decl
    | states_decl
    ;

startat_decl
    : STARTAT COLON keyword_or_string
    ;

comment_decl
    : COMMENT COLON keyword_or_string
    ;

state_stmt
    : comment_decl
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
    | seconds_path_decl
    | timestamp_decl
    | timestamp_path_decl
    | items_path_decl
    | item_processor_decl
    | max_concurrency_decl
    | branches_decl
    | parameters_decl
    | retry_decl
    | catch_decl
    | result_selector_decl
    ;

states_decl
    : STATES
      COLON
      LBRACE
      state_decl (COMMA state_decl)*
      RBRACE
    ;

state_name
    : keyword_or_string
    ;

// TODO: avoid redefinitions? -> check listener ok?
state_decl
    : state_name
      COLON
      state_decl_body
    ;

state_decl_body
    : LBRACE
      state_stmt (COMMA state_stmt)*
      RBRACE
    ;

type_decl
    : TYPE COLON state_type
    ;

next_decl
    : NEXT COLON keyword_or_string
    ;

resource_decl
    : RESOURCE COLON keyword_or_string
    ;

input_path_decl
    : INPUTPATH COLON keyword_or_string
    ;

result_decl
    : RESULT COLON json_value_decl
    ;

result_path_decl
    : RESULTPATH COLON keyword_or_string // TODO keywords too?
    ;

output_path_decl
    : OUTPUTPATH COLON keyword_or_string
    ;

end_decl
    : END COLON (TRUE | FALSE)
    ;

default_decl
    : DEFAULT COLON keyword_or_string
    ;

error_decl
    : ERROR COLON keyword_or_string
    ;

cause_decl
    : CAUSE COLON keyword_or_string
    ;

seconds_decl
    : SECONDS COLON INT
    ;

seconds_path_decl
    : SECONDSPATH COLON keyword_or_string
    ;

timestamp_decl
    : TIMESTAMP COLON keyword_or_string
    ;

timestamp_path_decl
    : TIMESTAMPPATH COLON keyword_or_string
    ;

items_path_decl
    : ITEMSPATH COLON keyword_or_string
    ;

max_concurrency_decl
    : MAXCONCURRENCY COLON INT
    ;

parameters_decl
    : PARAMETERS COLON payload_tmpl_decl
    ;

payload_tmpl_decl
    : LBRACE payload_binding (COMMA payload_binding)* RBRACE
    | LBRACK RBRACK
    ;

payload_binding
    : STRINGDOLLAR COLON STRINGPATH               #payload_binding_path
    | STRINGDOLLAR COLON STRINGPATHCONTEXTOBJ     #payload_binding_path_context_obj
    | STRINGDOLLAR COLON intrinsic_func           #payload_binding_intrinsic_func
    | keyword_or_string COLON payload_value_decl  #payload_binding_value
    ;

intrinsic_func
    : STRING
    ;

payload_arr_decl
    : LBRACK payload_value_decl (COMMA payload_value_decl)* RBRACK
    | LBRACK RBRACK
    ;

payload_value_decl
    : payload_binding
    | payload_arr_decl
    | payload_tmpl_decl
    | payload_value_lit
    ;

payload_value_lit
    : NUMBER             #payload_value_float
    | INT                #payload_value_int
    | (TRUE | FALSE)     #payload_value_bool
    | NULL               #payload_value_null
    | keyword_or_string  #payload_value_str
    ;

result_selector_decl
    : RESULTSELECTOR COLON payload_tmpl_decl
    ;

state_type
    : TASK
    | PASS
    | CHOICE
    | FAIL
    | SUCCEED
    | WAIT
    | MAP
    | PARALLEL
    ;

choices_decl
    : CHOICES
      COLON
      LBRACK
      choice_rule (COMMA choice_rule)*
      RBRACK
    ;

choice_rule
    : LBRACE
      choice_rule_stmt (COMMA choice_rule_stmt)*
      RBRACE
    ;

choice_rule_stmt
    : comparison
    | comparison_composite
    | next_decl
    ;

comparison
    : comparison_stmt (COMMA comparison_stmt)+
    ;

comparison_stmt
    : variable_decl
    | comparison_func
    ;

comparison_composite
// TODO: this allows for Next definitions in nested choice_rules, is this supported at parse time?
    : choice_operator COLON
      ( choice_rule
      | LBRACK
        choice_rule (COMMA choice_rule)+
        RBRACK
      )
    ;

variable_decl
    : VARIABLE COLON keyword_or_string
    ;

comparison_func
    : comparison_op COLON json_value_decl
    ;

branches_decl
    : BRANCHES
      COLON
      LBRACK
      program_decl (COMMA program_decl)*
      RBRACK
    ;

item_processor_decl
    : ITEMPROCESSOR
      COLON
      LBRACE
      item_processor_item (COMMA item_processor_item)*
      RBRACE
    ;

item_processor_item
    : processor_config_decl
    | startat_decl
    | states_decl
    | comment_decl
    ;

processor_config_decl
    : PROCESSORCONFIG
      COLON
      LBRACE
      ( mode_decl
      | json_binding  // TODO
      )*
      RBRACE
    ;

mode_decl
    : MODE COLON mode_type
    ;

mode_type
    : INLINE
    ;

retry_decl
    : RETRY
      COLON
      LBRACK
      retrier_decl (COMMA retry_decl)*
      RBRACK
    ;

retrier_decl
    : LBRACE
      retrier_stmt (COMMA retrier_stmt)*
      RBRACE
    ;

retrier_stmt
    : error_equals_decl
    | interval_seconds_decl
    | max_attempts_decl
    | backoff_rate_decl
    ;

error_equals_decl
    : ERROREQUALS
      COLON
      LBRACK
      error_name (COMMA error_name)*
      RBRACK
    ;

interval_seconds_decl
    : INTERVALSECONDS COLON INT
    ;

max_attempts_decl
    : MAXATTEMPTS COLON INT
    ;

backoff_rate_decl
    : BACKOFFRATE COLON NUMBER
    ;

catch_decl
    : CATCH
      COLON
      LBRACK
      catcher_decl (COMMA catcher_decl)*
      RBRACK
    ;

catcher_decl
    : LBRACE
      catcher_stmt (COMMA catcher_stmt)*
      RBRACE
    ;

catcher_stmt
    : error_equals_decl
    | result_path_decl
    | next_decl
    ;

comparison_op
    : BOOLEANEQUALS
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

choice_operator
    : NOT
    | AND
    | OR
    ;

states_error_name
    : ERRORNAMEStatesALL
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
    ;

error_name
    : states_error_name
    | keyword_or_string
    ;

json_obj_decl
   : LBRACE json_binding (COMMA json_binding)* RBRACE
   | LBRACE RBRACE
   ;

json_binding
   : keyword_or_string COLON json_value_decl
   ;

json_arr_decl
   : LBRACK json_value_decl (COMMA json_value_decl)* RBRACK
   | LBRACK RBRACK
   ;

json_value_decl
   : NUMBER
   | INT
   | TRUE
   | FALSE
   | NULL
   | json_binding
   | json_arr_decl
   | json_obj_decl
   | keyword_or_string
   ;

keyword_or_string // TODO: check keywords can be used as strings.
    : STRING
    | STRINGDOLLAR
    | STRINGPATH
    | STRINGPATHCONTEXTOBJ
    //
    | COMMENT
    | STATES
    | STARTAT
    | NEXTSTATE
    | TYPE
    | TASK
    | CHOICE
    | CHOICES
    | FAIL
    | WAIT
    | PARALLEL
    | MAP
    | SUCCEED
    | VARIABLE
    | RESOURCE
    | RESULT
    | END
    | CAUSE
    | ERROR
    | DEFAULT
    | ITEMSPATH
    | MODE
    | PROCESSORCONFIG
    | INLINE
    | OUTPUTPATH
    | RESULTPATH
    | INPUTPATH
    | SECONDSPATH
    | SECONDS
    | TIMESTAMPPATH
    | TIMESTAMP
    | RETRY
    | ERROREQUALS
    | INTERVALSECONDS
    | MAXATTEMPTS
    | BACKOFFRATE
    | CATCH
    //
    | comparison_func
    | choice_operator
    | states_error_name
    ;
