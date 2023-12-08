lexer grammar ASLIntrinsicLexer;

DOLLAR: '$';
DOT: '.';
STAR: '*';
COMMA: ',';
LPAREN: '(';
RPAREN: ')';
LBRACK: '[';
RBRACK: ']';
LDIAM: '<';
RDIAM: '>';
ATDOT: '@.';
ATDOTLENGTHDASH: '@.length-';
ANDAND: '&&';
OROR: '||';
EQEQ: '==';
EQ: '=';

TRUE: 'true';
FALSE: 'false';

States: 'States';
Format: 'Format';
StringToJson: 'StringToJson';
JsonToString: 'JsonToString';
Array: 'Array';
ArrayPartition: 'ArrayPartition';
ArrayContains: 'ArrayContains';
ArrayRange: 'ArrayRange';
ArrayGetItem: 'ArrayGetItem';
ArrayLength: 'ArrayLength';
ArrayUnique: 'ArrayUnique';
Base64Encode: 'Base64Encode';
Base64Decode: 'Base64Decode';
Hash: 'Hash';
JsonMerge: 'JsonMerge';
MathRandom: 'MathRandom';
MathAdd: 'MathAdd';
StringSplit: 'StringSplit';
UUID: 'UUID';


STRING
   : '\'' (ESC | SAFECODEPOINT)*? '\''
   ;

fragment ESC
   : '\\' (UNICODE | .)
   ;
fragment UNICODE
   : 'u' HEX HEX HEX HEX
   ;
fragment HEX
   : [0-9a-fA-F]
   ;
fragment SAFECODEPOINT
   : ~ ['\\\u0000-\u001F]
   ;

INT
   : '-'? ('0' | [1-9] [0-9]*)
   ;

NUMBER
   : '-'? INT ('.' [0-9] +)? EXP?
   ;

fragment EXP
   : [Ee] [+\-]? INT
   ;

IDENTIFIER
    : ([0-9a-zA-Z_] | UNICODE)+
    ;

WS
   : [ \t\n] + -> skip
   ;