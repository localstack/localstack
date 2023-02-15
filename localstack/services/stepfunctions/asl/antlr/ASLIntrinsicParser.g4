// TODO: playground grammar.

parser grammar ASLIntrinsicParser;

options {
    tokenVocab=ASLIntrinsicLexer;
}

// TODO.
compilation_unit
    : ( member
      | member_access
      )+
      EOF?
    ;

// TODO. func calls, args, etc.
// TODO json paths https://github.com/json-path/JsonPath
member_access
    : member DOT (member | member_access)
    ;

member
    : DOLLAR
    | IDENTIFIER
    ;
