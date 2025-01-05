// $antlr-format alignTrailingComments true, columnLimit 150, maxEmptyLinesToKeep 1, reflowComments false, useTab false
// $antlr-format allowShortRulesOnASingleLine true, allowShortBlocksOnASingleLine true, minEmptyLines 0, alignSemicolons ownLine
// $antlr-format alignColons trailing, singleLineOverrulesHangingColon true, alignLexerCommands true, alignLabels true, alignTrailers true

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

VERSION: '"Version"';

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

CONDITION: '"Condition"';

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

TIMEOUTSECONDS: '"TimeoutSeconds"';

TIMEOUTSECONDSPATH: '"TimeoutSecondsPath"';

HEARTBEATSECONDS: '"HeartbeatSeconds"';

HEARTBEATSECONDSPATH: '"HeartbeatSecondsPath"';

PROCESSORCONFIG: '"ProcessorConfig"';

MODE: '"Mode"';

INLINE: '"INLINE"';

DISTRIBUTED: '"DISTRIBUTED"';

EXECUTIONTYPE: '"ExecutionType"';

STANDARD: '"STANDARD"';

ITEMPROCESSOR: '"ItemProcessor"';

ITERATOR: '"Iterator"';

ITEMSELECTOR: '"ItemSelector"';

MAXCONCURRENCYPATH: '"MaxConcurrencyPath"';

MAXCONCURRENCY: '"MaxConcurrency"';

RESOURCE: '"Resource"';

INPUTPATH: '"InputPath"';

OUTPUTPATH: '"OutputPath"';

ITEMS: '"Items"';

ITEMSPATH: '"ItemsPath"';

RESULTPATH: '"ResultPath"';

RESULT: '"Result"';

PARAMETERS: '"Parameters"';

CREDENTIALS: '"Credentials"';

ROLEARN: '"RoleArn"';

ROLEARNPATH: '"RoleArn.$"';

RESULTSELECTOR: '"ResultSelector"';

ITEMREADER: '"ItemReader"';

READERCONFIG: '"ReaderConfig"';

INPUTTYPE: '"InputType"';

CSVHEADERLOCATION: '"CSVHeaderLocation"';

CSVHEADERS: '"CSVHeaders"';

MAXITEMS: '"MaxItems"';

MAXITEMSPATH: '"MaxItemsPath"';

TOLERATEDFAILURECOUNT: '"ToleratedFailureCount"';

TOLERATEDFAILURECOUNTPATH: '"ToleratedFailureCountPath"';

TOLERATEDFAILUREPERCENTAGE: '"ToleratedFailurePercentage"';

TOLERATEDFAILUREPERCENTAGEPATH: '"ToleratedFailurePercentagePath"';

LABEL: '"Label"';

RESULTWRITER: '"ResultWriter"';

NEXT: '"Next"';

END: '"End"';

CAUSE: '"Cause"';

CAUSEPATH: '"CausePath"';

ERROR: '"Error"';

ERRORPATH: '"ErrorPath"';

// Retry.
RETRY: '"Retry"';

ERROREQUALS: '"ErrorEquals"';

INTERVALSECONDS: '"IntervalSeconds"';

MAXATTEMPTS: '"MaxAttempts"';

BACKOFFRATE: '"BackoffRate"';

MAXDELAYSECONDS: '"MaxDelaySeconds"';

JITTERSTRATEGY: '"JitterStrategy"';

FULL: '"FULL"';

NONE: '"NONE"';

// Catch.
CATCH: '"Catch"';

// Query Language.
QUERYLANGUAGE: '"QueryLanguage"';

JSONPATH: '"JSONPath"';

JSONATA: '"JSONata"';

// Assign.
ASSIGN: '"Assign"';

// Output.
OUTPUT: '"Output"';

// Arguments.
ARGUMENTS: '"Arguments"';

// ErrorNames
ERRORNAMEStatesALL: '"States.ALL"';

ERRORNAMEStatesDataLimitExceeded: '"States.DataLimitExceeded"';

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

ERRORNAMEStatesQueryEvaluationError: '"States.QueryEvaluationError"';

// Read-only:
ERRORNAMEStatesRuntime: '"States.Runtime"';

// Strings.
STRINGDOLLAR: '"' (ESC | SAFECODEPOINT)* '.$"';

STRINGPATHCONTEXTOBJ: '"$$' (ESC | SAFECODEPOINT)* '"';

STRINGPATH: '"$"' | '"$' ('.' | '[') (ESC | SAFECODEPOINT)* '"';

STRINGVAR: '"$' [a-zA-Z_] (ESC | SAFECODEPOINT)* '"';

STRINGINTRINSICFUNC: '"States.' (ESC | SAFECODEPOINT)+ '(' (ESC | SAFECODEPOINT)* ')"';

STRINGJSONATA: LJSONATA (ESC | SAFECODEPOINT)* RJSONATA;

STRING: '"' (ESC | SAFECODEPOINT)* '"';

fragment ESC: '\\' (["\\/bfnrt] | UNICODE);

fragment UNICODE: 'u' HEX HEX HEX HEX;

fragment HEX: [0-9a-fA-F];

fragment SAFECODEPOINT: ~ ["\\\u0000-\u001F];

fragment LJSONATA: '"{%';

fragment RJSONATA: '%}"';

// Numbers.
INT: '0' | [1-9] [0-9]*;

NUMBER: '-'? INT ('.' [0-9]+)? EXP?;

fragment EXP: [Ee] [+\-]? INT;

// Whitespace.
WS: [ \t\n\r]+ -> skip;