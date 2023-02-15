// TODO: playground lexer.

lexer grammar ASLIntrinsicLexer;

DOLLAR: '$';
DDOLLAR: '$$';
DOT: '.';
COMMA: ',';
LPAREN: '(';
RPAREN: ')';
LBRACK: '[';
RBRACK: ']';
LBRACE: '{';
RBRACE: '}';


IDENTIFIER
    : ([0-9a-zA-Z_] | UNICODE)+
    ;

// TODO
STRING
   : '\\"' (ESC | SAFECODEPOINT)* '\\"'
   ;


fragment ESC
   : '\\' (["\\/bfnrt] | UNICODE)
   ;
fragment UNICODE
   : 'u' HEX HEX HEX HEX
   ;
fragment HEX
   : [0-9a-fA-F]
   ;
fragment SAFECODEPOINT
   : ~ ["\\\u0000-\u001F]
   ;


NUMBER
   : '-'? INT ('.' [0-9] +)? EXP?
   ;


fragment INT
   : '0' | [1-9] [0-9]*
   ;

fragment EXP
   : [Ee] [+\-]? INT
   ;

WS
   : [ \t] + -> skip
   ;