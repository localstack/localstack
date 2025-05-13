// $antlr-format alignTrailingComments true, columnLimit 150, maxEmptyLinesToKeep 1, reflowComments false, useTab false
// $antlr-format allowShortRulesOnASingleLine true, allowShortBlocksOnASingleLine true, minEmptyLines 0, alignSemicolons ownLine
// $antlr-format alignColons trailing, singleLineOverrulesHangingColon true, alignLexerCommands true, alignLabels true, alignTrailers true

lexer grammar DSLLexer;

// Comments:
LINECOMMENT: '#' ~[\r\n\f]* -> skip;

JSONATA: 'jsonata(' ~[)]* ')';

// Symbols.
ARROW: '->';
EQUALS: '=';
COMMA: ',';
COLON: ':';
LPAREN: '(';
RPAREN: ')';
LBRACK: '[';
RBRACK: ']';
LBRACE: '{';
RBRACE: '}';

// Literals.
TRUE: 'true';
FALSE: 'false';
NULL: 'null';

// Keywords.
WITH: 'with';
AS: 'as';
FAIL: 'fail';
ERROR: 'error';
CAUSE: 'cause';
LAMBDA: 'lambda';
PARAMETERS: 'parameters';
CATCH: 'catch';


STRINGPATH: '"$"' | '"$' ('.' | '[') (ESC | SAFECODEPOINT)* '"';

VAR: '$' [a-zA-Z_] (ESC | SAFECODEPOINT)*;

STRING: '"' (ESC | SAFECODEPOINT)* '"';

fragment ESC: '\\' (["\\/bfnrt] | UNICODE);

fragment UNICODE: 'u' HEX HEX HEX HEX;

fragment HEX: [0-9a-fA-F];

fragment SAFECODEPOINT: ~ ["\\\u0000-\u001F];


// Numbers.
INT: '0' | [1-9] [0-9]*;

NUMBER: '-'? INT ('.' [0-9]+)? EXP?;

fragment EXP: [Ee] [+\-]? INT;

IDEN: [a-zA-Z_0-9-]+;


// Whitespace.
WS: [ \t\n\r]+ -> skip;

TOK: .;
