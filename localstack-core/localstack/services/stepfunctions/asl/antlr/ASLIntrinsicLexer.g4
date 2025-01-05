// $antlr-format alignTrailingComments true, columnLimit 150, maxEmptyLinesToKeep 1, reflowComments false, useTab false
// $antlr-format allowShortRulesOnASingleLine true, allowShortBlocksOnASingleLine true, minEmptyLines 0, alignSemicolons ownLine
// $antlr-format alignColons trailing, singleLineOverrulesHangingColon true, alignLexerCommands true, alignLabels true, alignTrailers true

lexer grammar ASLIntrinsicLexer;

CONTEXT_PATH_STRING: DOLLAR DOLLAR JSON_PATH_BODY;

JSON_PATH_STRING: DOLLAR JSON_PATH_BODY;

STRING_VARIABLE: DOLLAR IDENTIFIER JSON_PATH_BODY;

// TODO: JSONPath body composition may need strenghening to support features such as filtering conditions.
fragment JSON_PATH_BODY: JSON_PATH_BRACK? (DOT IDENTIFIER? JSON_PATH_BRACK?)*;

fragment JSON_PATH_BRACK: '[' (JSON_PATH_BRACK | ~[\]])* ']';

DOLLAR : '$';
LPAREN : '(';
RPAREN : ')';
COMMA  : ',';
DOT    : '.';

TRUE  : 'true';
FALSE : 'false';

States         : 'States';
Format         : 'Format';
StringToJson   : 'StringToJson';
JsonToString   : 'JsonToString';
Array          : 'Array';
ArrayPartition : 'ArrayPartition';
ArrayContains  : 'ArrayContains';
ArrayRange     : 'ArrayRange';
ArrayGetItem   : 'ArrayGetItem';
ArrayLength    : 'ArrayLength';
ArrayUnique    : 'ArrayUnique';
Base64Encode   : 'Base64Encode';
Base64Decode   : 'Base64Decode';
Hash           : 'Hash';
JsonMerge      : 'JsonMerge';
MathRandom     : 'MathRandom';
MathAdd        : 'MathAdd';
StringSplit    : 'StringSplit';
UUID           : 'UUID';

STRING: '\'' (ESC | SAFECODEPOINT)*? '\'';

fragment ESC           : '\\' (UNICODE | .);
fragment UNICODE       : 'u' HEX HEX HEX HEX;
fragment HEX           : [0-9a-fA-F];
fragment SAFECODEPOINT : ~ ['\\\u0000-\u001F];

INT: '-'? ('0' | [1-9] [0-9]*);

NUMBER: '-'? INT ('.' [0-9]+)? EXP?;

fragment EXP: [Ee] [+\-]? INT;

IDENTIFIER: ([0-9a-zA-Z_] | UNICODE)+;

WS: [ \t\n]+ -> skip;