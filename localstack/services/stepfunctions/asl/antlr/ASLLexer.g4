lexer grammar ASLLexer;

// Symbols.
COMMA: ',';
COLON: ':';
LBRACK: '[';
RBRACK: ']';
LBRACE: '{';
RBRACE: '}';

// Literals.
TRUE: 'true';
FALSE: 'false';
NULL: 'null';

// Keywords.
COMMENT: '"Comment"';
STATES: '"States"';
STARTAT: '"StartAt"';
NEXTSTATE: '"NextState"';

TYPE: '"Type"';
TASK: '"Task"';
CHOICE: '"Choice"';
FAIL: '"Fail"';
SUCCEED: '"Succeed"';
PASS: '"Pass"';
WAIT: '"Wait"';
PARALLEL: '"Parallel"';
MAP: '"Map"';

CHOICES: '"Choices"';
VARIABLE: '"Variable"';
DEFAULT: '"Default"';
BRANCHES: '"Branches"';

AND: '"And"';
BOOLEANEQUALS: '"BooleanEquals"';
BOOLEANQUALSPATH: '"BooleanEqualsPath"';
ISBOOLEAN: '"IsBoolean"';
ISNULL: '"IsNull"';
ISNUMERIC: '"IsNumeric"';
ISPRESENT: '"IsPresent"';
ISSTRING: '"IsString"';
ISTIMESTAMP: '"IsTimestamp"';
NOT: '"Not"';
NUMERICEQUALS: '"NumericEquals"';
NUMERICEQUALSPATH: '"NumericEqualsPath"';
NUMERICGREATERTHAN: '"NumericGreaterThan"';
NUMERICGREATERTHANPATH: '"NumericGreaterThanPath"';
NUMERICGREATERTHANEQUALS: '"NumericGreaterThanEquals"';
NUMERICGREATERTHANEQUALSPATH: '"NumericGreaterThanEqualsPath"';
NUMERICLESSTHAN: '"NumericLessThan"';
NUMERICLESSTHANPATH: '"NumericLessThanPath"';
NUMERICLESSTHANEQUALS: '"NumericLessThanEquals"';
NUMERICLESSTHANEQUALSPATH: '"NumericLessThanEqualsPath"';
OR: '"Or"';
STRINGEQUALS: '"StringEquals"';
STRINGEQUALSPATH: '"StringEqualsPath"';
STRINGGREATERTHAN: '"StringGreaterThan"';
STRINGGREATERTHANPATH: '"StringGreaterThanPath"';
STRINGGREATERTHANEQUALS: '"StringGreaterThanEquals"';
STRINGGREATERTHANEQUALSPATH: '"StringGreaterThanEqualsPath"';
STRINGLESSTHAN: '"StringLessThan"';
STRINGLESSTHANPATH: '"StringLessThanPath"';
STRINGLESSTHANEQUALS: '"StringLessThanEquals"';
STRINGLESSTHANEQUALSPATH: '"StringLessThanEqualsPath"';
STRINGMATCHES: '"StringMatches"';
TIMESTAMPEQUALS: '"TimestampEquals"';
TIMESTAMPEQUALSPATH: '"TimestampEqualsPath"';
TIMESTAMPGREATERTHAN: '"TimestampGreaterThan"';
TIMESTAMPGREATERTHANPATH: '"TimestampGreaterThanPath"';
TIMESTAMPGREATERTHANEQUALS: '"TimestampGreaterThanEquals"';
TIMESTAMPGREATERTHANEQUALSPATH: '"TimestampGreaterThanEqualsPath"';
TIMESTAMPLESSTHAN: '"TimestampLessThan"';
TIMESTAMPLESSTHANPATH: '"TimestampLessThanPath"';
TIMESTAMPLESSTHANEQUALS: '"TimestampLessThanEquals"';
TIMESTAMPLESSTHANEQUALSPATH: '"TimestampLessThanEqualsPath"';

SECONDSPATH: '"SecondsPath"';
SECONDS: '"Seconds"';
TIMESTAMPPATH: '"TimestampPath"';
TIMESTAMP: '"Timestamp"';

PROCESSORCONFIG: '"ProcessorConfig"';
MODE: '"Mode"';
INLINE: '"INLINE"';

ITEMPROCESSOR: '"ItemProcessor"';
MAXCONCURRENCY: '"MaxConcurrency"';

RESOURCE: '"Resource"';
INPUTPATH: '"InputPath"';
OUTPUTPATH: '"OutputPath"';
ITEMSPATH: '"ItemsPath"';
RESULTPATH: '"ResultPath"';
RESULT: '"Result"';
PARAMETERS: '"Parameters"';
RESULTSELECTOR: '"ResultSelector"';

NEXT: '"Next"';
END: '"End"';

CAUSE: '"Cause"';
ERROR: '"Error"';

// Retry.
RETRY: '"Retry"';
ERROREQUALS: '"ErrorEquals"';
INTERVALSECONDS: '"IntervalSeconds"';
MAXATTEMPTS: '"MaxAttempts"';
BACKOFFRATE: '"BackoffRate"';

// Catch.
CATCH: '"Catch"';

// ErrorNames
ERRORNAMEStatesALL: '"States.ALL"';
ERRORNAMEStatesHeartbeatTimeout: '"States.HeartbeatTimeout"';
ERRORNAMEStatesTimeout: '"States.Timeout"';
ERRORNAMEStatesTaskFailed: '"States.TaskFailed"';
ERRORNAMEStatesPermissions: '"States.Permissions"';
ERRORNAMEStatesResultPathMatchFailure: '"States.ResultPathMatchFailure"';
ERRORNAMEStatesParameterPathFailure: '"States.ParameterPathFailure"';
ERRORNAMEStatesBranchFailed: '"States.BranchFailed"';
ERRORNAMEStatesNoChoiceMatched: '"States.NoChoiceMatched"';
ERRORNAMEStatesIntrinsicFailure: '"States.IntrinsicFailure"';
ERRORNAMEStatesExceedToleratedFailureThreshold: '"States.ExceedToleratedFailureThreshold"';
ERRORNAMEStatesItemReaderFailed: '"States.ItemReaderFailed"';
ERRORNAMEStatesResultWriterFailed: '"States.ResultWriterFailed"';

// Strings.

STRINGDOLLAR
    : '"' (ESC | SAFECODEPOINT)* '.$"'
    ;

STRINGPATHCONTEXTOBJ
    : '"$$.' (ESC | SAFECODEPOINT)* '"'
    ;

STRINGPATH
    : '"$.' (ESC | SAFECODEPOINT)* '"'
    ;

STRING
    : '"' (ESC | SAFECODEPOINT)* '"'
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

// Numbers.
INT
    : '0' | [1-9] [0-9]*
    ;

NUMBER
    : '-'? INT ('.' [0-9] +)? EXP?
    ;

fragment EXP
    : [Ee] [+\-]? INT
    ;

// Whitespace.
WS
    : [ \t\n\r] + -> skip
    ;