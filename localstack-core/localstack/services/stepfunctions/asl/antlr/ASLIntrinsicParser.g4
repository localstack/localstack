// $antlr-format alignTrailingComments true, columnLimit 150, maxEmptyLinesToKeep 1, reflowComments false, useTab false
// $antlr-format allowShortRulesOnASingleLine true, allowShortBlocksOnASingleLine true, minEmptyLines 0, alignSemicolons ownLine
// $antlr-format alignColons trailing, singleLineOverrulesHangingColon true, alignLexerCommands true, alignLabels true, alignTrailers true

parser grammar ASLIntrinsicParser;

options {
    tokenVocab = ASLIntrinsicLexer;
}

func_decl: states_func_decl EOF;

states_func_decl: States DOT state_fun_name func_arg_list;

state_fun_name:
    Format
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

func_arg_list: LPAREN func_arg (COMMA func_arg)* RPAREN | LPAREN RPAREN;

func_arg:
    STRING                # func_arg_string
    | INT                 # func_arg_int
    | NUMBER              # func_arg_float
    | (TRUE | FALSE)      # func_arg_bool
    | CONTEXT_PATH_STRING # func_arg_context_path
    | JSON_PATH_STRING    # func_arg_json_path
    | STRING_VARIABLE     # func_arg_var
    | states_func_decl    # func_arg_func_decl
;