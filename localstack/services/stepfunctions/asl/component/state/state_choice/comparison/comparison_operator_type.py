from enum import Enum

from localstack.services.stepfunctions.asl.antlr.runtime.ASLLexer import ASLLexer


class ComparisonOperatorType(Enum):
    BooleanEquals = ASLLexer.BOOLEANEQUALS
    BooleanEqualsPath = ASLLexer.BOOLEANQUALSPATH
    IsBoolean = ASLLexer.ISBOOLEAN
    IsNull = ASLLexer.ISNULL
    IsNumeric = ASLLexer.ISNUMERIC
    IsPresent = ASLLexer.ISPRESENT
    IsString = ASLLexer.ISSTRING
    IsTimestamp = ASLLexer.ISTIMESTAMP
    NumericEquals = ASLLexer.NUMERICEQUALS
    NumericEqualsPath = ASLLexer.NUMERICEQUALSPATH
    NumericGreaterThan = ASLLexer.NUMERICGREATERTHAN
    NumericGreaterThanPath = ASLLexer.NUMERICGREATERTHANPATH
    NumericGreaterThanEquals = ASLLexer.NUMERICGREATERTHANEQUALS
    NumericGreaterThanEqualsPath = ASLLexer.NUMERICGREATERTHANEQUALSPATH
    NumericLessThan = ASLLexer.NUMERICLESSTHAN
    NumericLessThanPath = ASLLexer.NUMERICLESSTHANPATH
    NumericLessThanEquals = ASLLexer.NUMERICLESSTHANEQUALS
    NumericLessThanEqualsPath = ASLLexer.NUMERICLESSTHANEQUALSPATH
    StringEquals = ASLLexer.STRINGEQUALS
    StringEqualsPath = ASLLexer.STRINGEQUALSPATH
    StringGreaterThan = ASLLexer.STRINGGREATERTHAN
    StringGreaterThanPath = ASLLexer.STRINGGREATERTHANPATH
    StringGreaterThanEquals = ASLLexer.STRINGGREATERTHANEQUALS
    StringGreaterThanEqualsPath = ASLLexer.STRINGGREATERTHANEQUALSPATH
    StringLessThan = ASLLexer.STRINGLESSTHAN
    StringLessThanPath = ASLLexer.STRINGLESSTHANPATH
    StringLessThanEquals = ASLLexer.STRINGLESSTHANEQUALS
    StringLessThanEqualsPath = ASLLexer.STRINGLESSTHANEQUALSPATH
    StringMatches = ASLLexer.STRINGMATCHES
    TimestampEquals = ASLLexer.TIMESTAMPEQUALS
    TimestampEqualsPath = ASLLexer.TIMESTAMPEQUALSPATH
    TimestampGreaterThan = ASLLexer.TIMESTAMPGREATERTHAN
    TimestampGreaterThanPath = ASLLexer.TIMESTAMPGREATERTHANPATH
    TimestampGreaterThanEquals = ASLLexer.TIMESTAMPGREATERTHANEQUALS
    TimestampGreaterThanEqualsPath = ASLLexer.TIMESTAMPGREATERTHANEQUALSPATH
    TimestampLessThan = ASLLexer.TIMESTAMPLESSTHAN
    TimestampLessThanPath = ASLLexer.TIMESTAMPLESSTHANPATH
    TimestampLessThanEquals = ASLLexer.TIMESTAMPLESSTHANEQUALS
    TimestampLessThanEqualsPath = ASLLexer.TIMESTAMPLESSTHANEQUALSPATH
