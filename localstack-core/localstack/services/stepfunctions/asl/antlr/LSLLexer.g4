// $antlr-format alignTrailingComments true, columnLimit 150, maxEmptyLinesToKeep 1, reflowComments false, useTab false
// $antlr-format allowShortRulesOnASingleLine true, allowShortBlocksOnASingleLine true, minEmptyLines 0, alignSemicolons ownLine
// $antlr-format alignColons trailing, singleLineOverrulesHangingColon true, alignLexerCommands true, alignLabels true, alignTrailers true

lexer grammar LSLLexer;

// Comments:
LINECOMMENT: '#' ~[\r\n\f]* -> skip;

JSONATA: 'jsonata(' ~[)]* ')';

// ErrorNames
ERRORNAMEStatesALL: 'States.ALL';
ERRORNAMEStatesDataLimitExceeded: 'States.DataLimitExceeded';
ERRORNAMEStatesHeartbeatTimeout: 'States.HeartbeatTimeout';
ERRORNAMEStatesTimeout: 'States.Timeout';
ERRORNAMEStatesTaskFailed: 'States.TaskFailed';
ERRORNAMEStatesPermissions: 'States.Permissions';
ERRORNAMEStatesResultPathMatchFailure: 'States.ResultPathMatchFailure';
ERRORNAMEStatesParameterPathFailure: 'States.ParameterPathFailure';
ERRORNAMEStatesBranchFailed: 'States.BranchFailed';
ERRORNAMEStatesNoChoiceMatched: 'States.NoChoiceMatched';
ERRORNAMEStatesIntrinsicFailure: 'States.IntrinsicFailure';
ERRORNAMEStatesExceedToleratedFailureThreshold: 'States.ExceedToleratedFailureThreshold';
ERRORNAMEStatesItemReaderFailed: 'States.ItemReaderFailed';
ERRORNAMEStatesResultWriterFailed: 'States.ResultWriterFailed';
ERRORNAMEStatesQueryEvaluationError: 'States.QueryEvaluationError';

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
WHERE: 'where';
AS: 'as';
FAIL: 'fail';
OUTPUT: 'output';
RETURN: 'return';
ERROR: 'error';
CAUSE: 'cause';
LAMBDA: 'lambda';
ARGUMENTS: 'arguments';
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
