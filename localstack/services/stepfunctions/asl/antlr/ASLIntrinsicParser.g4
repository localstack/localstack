parser grammar ASLIntrinsicParser;

options {
    tokenVocab=ASLIntrinsicLexer;
}

func_decl
    : states_func_decl
    ;

states_func_decl
    : States DOT state_fun_name func_arg_list
    ;

state_fun_name
    : Format
    | StringToJson
    | JsonToString
    | Array
    | ArrayPartition
    | ArrayContains
    | ArrayRange
    | ArrayGetItem
    | ArrayLength
    | ArrayUnique
    | Base64Encode
    | Base64Decode
    | Hash
    | JsonMerge
    | MathRandom
    | MathAdd
    | StringSplit
    | UUID
    ;

func_arg_list
    : LPAREN func_arg (COMMA func_arg)* RPAREN
    | LPAREN RPAREN
    ;

func_arg
    : STRING          #func_arg_string
    | INT             #func_arg_int
    | NUMBER          #func_arg_float
    | (TRUE | FALSE)  #func_arg_bool
    | context_path    #func_arg_context_path
    | json_path       #func_arg_json_path
    | func_decl       #func_arg_func_decl
    ;

context_path
    :  DOLLAR json_path
    ;

json_path
    : DOLLAR DOT json_path_part (DOT json_path_part)*
    ;

json_path_part
    : json_path_iden
    | json_path_iden_qual
    ;

json_path_iden
    : identifier
    ;

json_path_iden_qual
    : json_path_iden json_path_qual
    ;

json_path_qual
    : LBRACK RBRACK                  #json_path_qual_void
    | LBRACK INT RBRACK              #json_path_qual_idx
    | LBRACK json_path_query RBRACK  #json_path_qual_query
    ;

json_path_query
    : STAR                                                # json_path_query_star
    | ATDOT json_path_iden
      ( (LDIAM | RDIAM | EQEQ) INT
      | EQ STRING
      )                                                   # json_path_query_cmp
    | ATDOTLENGTHDASH INT                                 # json_path_query_length
    | json_path_query ((ANDAND | OROR) json_path_query)+  # json_path_query_binary
    ;

identifier
    : IDENTIFIER
    // States.
    | state_fun_name
    ;
