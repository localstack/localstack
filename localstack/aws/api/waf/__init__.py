import sys
from datetime import datetime
from typing import List, Optional

if sys.version_info >= (3, 8):
    from typing import TypedDict
else:
    from typing_extensions import TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

Action = str
ChangeToken = str
Country = str
ErrorReason = str
HTTPMethod = str
HTTPVersion = str
HeaderName = str
HeaderValue = str
IPSetDescriptorValue = str
IPString = str
IgnoreUnsupportedType = bool
ManagedKey = str
MatchFieldData = str
MetricName = str
Negated = bool
NextMarker = str
PaginationLimit = int
ParameterExceptionParameter = str
PolicyString = str
RegexPatternString = str
ResourceArn = str
ResourceId = str
ResourceName = str
RulePriority = int
S3BucketName = str
S3ObjectUrl = str
TagKey = str
TagValue = str
URIString = str
errorMessage = str


class ChangeAction(str):
    INSERT = "INSERT"
    DELETE = "DELETE"


class ChangeTokenStatus(str):
    PROVISIONED = "PROVISIONED"
    PENDING = "PENDING"
    INSYNC = "INSYNC"


class ComparisonOperator(str):
    EQ = "EQ"
    NE = "NE"
    LE = "LE"
    LT = "LT"
    GE = "GE"
    GT = "GT"


class GeoMatchConstraintType(str):
    Country = "Country"


class GeoMatchConstraintValue(str):
    AF = "AF"
    AX = "AX"
    AL = "AL"
    DZ = "DZ"
    AS = "AS"
    AD = "AD"
    AO = "AO"
    AI = "AI"
    AQ = "AQ"
    AG = "AG"
    AR = "AR"
    AM = "AM"
    AW = "AW"
    AU = "AU"
    AT = "AT"
    AZ = "AZ"
    BS = "BS"
    BH = "BH"
    BD = "BD"
    BB = "BB"
    BY = "BY"
    BE = "BE"
    BZ = "BZ"
    BJ = "BJ"
    BM = "BM"
    BT = "BT"
    BO = "BO"
    BQ = "BQ"
    BA = "BA"
    BW = "BW"
    BV = "BV"
    BR = "BR"
    IO = "IO"
    BN = "BN"
    BG = "BG"
    BF = "BF"
    BI = "BI"
    KH = "KH"
    CM = "CM"
    CA = "CA"
    CV = "CV"
    KY = "KY"
    CF = "CF"
    TD = "TD"
    CL = "CL"
    CN = "CN"
    CX = "CX"
    CC = "CC"
    CO = "CO"
    KM = "KM"
    CG = "CG"
    CD = "CD"
    CK = "CK"
    CR = "CR"
    CI = "CI"
    HR = "HR"
    CU = "CU"
    CW = "CW"
    CY = "CY"
    CZ = "CZ"
    DK = "DK"
    DJ = "DJ"
    DM = "DM"
    DO = "DO"
    EC = "EC"
    EG = "EG"
    SV = "SV"
    GQ = "GQ"
    ER = "ER"
    EE = "EE"
    ET = "ET"
    FK = "FK"
    FO = "FO"
    FJ = "FJ"
    FI = "FI"
    FR = "FR"
    GF = "GF"
    PF = "PF"
    TF = "TF"
    GA = "GA"
    GM = "GM"
    GE = "GE"
    DE = "DE"
    GH = "GH"
    GI = "GI"
    GR = "GR"
    GL = "GL"
    GD = "GD"
    GP = "GP"
    GU = "GU"
    GT = "GT"
    GG = "GG"
    GN = "GN"
    GW = "GW"
    GY = "GY"
    HT = "HT"
    HM = "HM"
    VA = "VA"
    HN = "HN"
    HK = "HK"
    HU = "HU"
    IS = "IS"
    IN = "IN"
    ID = "ID"
    IR = "IR"
    IQ = "IQ"
    IE = "IE"
    IM = "IM"
    IL = "IL"
    IT = "IT"
    JM = "JM"
    JP = "JP"
    JE = "JE"
    JO = "JO"
    KZ = "KZ"
    KE = "KE"
    KI = "KI"
    KP = "KP"
    KR = "KR"
    KW = "KW"
    KG = "KG"
    LA = "LA"
    LV = "LV"
    LB = "LB"
    LS = "LS"
    LR = "LR"
    LY = "LY"
    LI = "LI"
    LT = "LT"
    LU = "LU"
    MO = "MO"
    MK = "MK"
    MG = "MG"
    MW = "MW"
    MY = "MY"
    MV = "MV"
    ML = "ML"
    MT = "MT"
    MH = "MH"
    MQ = "MQ"
    MR = "MR"
    MU = "MU"
    YT = "YT"
    MX = "MX"
    FM = "FM"
    MD = "MD"
    MC = "MC"
    MN = "MN"
    ME = "ME"
    MS = "MS"
    MA = "MA"
    MZ = "MZ"
    MM = "MM"
    NA = "NA"
    NR = "NR"
    NP = "NP"
    NL = "NL"
    NC = "NC"
    NZ = "NZ"
    NI = "NI"
    NE = "NE"
    NG = "NG"
    NU = "NU"
    NF = "NF"
    MP = "MP"
    NO = "NO"
    OM = "OM"
    PK = "PK"
    PW = "PW"
    PS = "PS"
    PA = "PA"
    PG = "PG"
    PY = "PY"
    PE = "PE"
    PH = "PH"
    PN = "PN"
    PL = "PL"
    PT = "PT"
    PR = "PR"
    QA = "QA"
    RE = "RE"
    RO = "RO"
    RU = "RU"
    RW = "RW"
    BL = "BL"
    SH = "SH"
    KN = "KN"
    LC = "LC"
    MF = "MF"
    PM = "PM"
    VC = "VC"
    WS = "WS"
    SM = "SM"
    ST = "ST"
    SA = "SA"
    SN = "SN"
    RS = "RS"
    SC = "SC"
    SL = "SL"
    SG = "SG"
    SX = "SX"
    SK = "SK"
    SI = "SI"
    SB = "SB"
    SO = "SO"
    ZA = "ZA"
    GS = "GS"
    SS = "SS"
    ES = "ES"
    LK = "LK"
    SD = "SD"
    SR = "SR"
    SJ = "SJ"
    SZ = "SZ"
    SE = "SE"
    CH = "CH"
    SY = "SY"
    TW = "TW"
    TJ = "TJ"
    TZ = "TZ"
    TH = "TH"
    TL = "TL"
    TG = "TG"
    TK = "TK"
    TO = "TO"
    TT = "TT"
    TN = "TN"
    TR = "TR"
    TM = "TM"
    TC = "TC"
    TV = "TV"
    UG = "UG"
    UA = "UA"
    AE = "AE"
    GB = "GB"
    US = "US"
    UM = "UM"
    UY = "UY"
    UZ = "UZ"
    VU = "VU"
    VE = "VE"
    VN = "VN"
    VG = "VG"
    VI = "VI"
    WF = "WF"
    EH = "EH"
    YE = "YE"
    ZM = "ZM"
    ZW = "ZW"


class IPSetDescriptorType(str):
    IPV4 = "IPV4"
    IPV6 = "IPV6"


class MatchFieldType(str):
    URI = "URI"
    QUERY_STRING = "QUERY_STRING"
    HEADER = "HEADER"
    METHOD = "METHOD"
    BODY = "BODY"
    SINGLE_QUERY_ARG = "SINGLE_QUERY_ARG"
    ALL_QUERY_ARGS = "ALL_QUERY_ARGS"


class MigrationErrorType(str):
    ENTITY_NOT_SUPPORTED = "ENTITY_NOT_SUPPORTED"
    ENTITY_NOT_FOUND = "ENTITY_NOT_FOUND"
    S3_BUCKET_NO_PERMISSION = "S3_BUCKET_NO_PERMISSION"
    S3_BUCKET_NOT_ACCESSIBLE = "S3_BUCKET_NOT_ACCESSIBLE"
    S3_BUCKET_NOT_FOUND = "S3_BUCKET_NOT_FOUND"
    S3_BUCKET_INVALID_REGION = "S3_BUCKET_INVALID_REGION"
    S3_INTERNAL_ERROR = "S3_INTERNAL_ERROR"


class ParameterExceptionField(str):
    CHANGE_ACTION = "CHANGE_ACTION"
    WAF_ACTION = "WAF_ACTION"
    WAF_OVERRIDE_ACTION = "WAF_OVERRIDE_ACTION"
    PREDICATE_TYPE = "PREDICATE_TYPE"
    IPSET_TYPE = "IPSET_TYPE"
    BYTE_MATCH_FIELD_TYPE = "BYTE_MATCH_FIELD_TYPE"
    SQL_INJECTION_MATCH_FIELD_TYPE = "SQL_INJECTION_MATCH_FIELD_TYPE"
    BYTE_MATCH_TEXT_TRANSFORMATION = "BYTE_MATCH_TEXT_TRANSFORMATION"
    BYTE_MATCH_POSITIONAL_CONSTRAINT = "BYTE_MATCH_POSITIONAL_CONSTRAINT"
    SIZE_CONSTRAINT_COMPARISON_OPERATOR = "SIZE_CONSTRAINT_COMPARISON_OPERATOR"
    GEO_MATCH_LOCATION_TYPE = "GEO_MATCH_LOCATION_TYPE"
    GEO_MATCH_LOCATION_VALUE = "GEO_MATCH_LOCATION_VALUE"
    RATE_KEY = "RATE_KEY"
    RULE_TYPE = "RULE_TYPE"
    NEXT_MARKER = "NEXT_MARKER"
    RESOURCE_ARN = "RESOURCE_ARN"
    TAGS = "TAGS"
    TAG_KEYS = "TAG_KEYS"


class ParameterExceptionReason(str):
    INVALID_OPTION = "INVALID_OPTION"
    ILLEGAL_COMBINATION = "ILLEGAL_COMBINATION"
    ILLEGAL_ARGUMENT = "ILLEGAL_ARGUMENT"
    INVALID_TAG_KEY = "INVALID_TAG_KEY"


class PositionalConstraint(str):
    EXACTLY = "EXACTLY"
    STARTS_WITH = "STARTS_WITH"
    ENDS_WITH = "ENDS_WITH"
    CONTAINS = "CONTAINS"
    CONTAINS_WORD = "CONTAINS_WORD"


class PredicateType(str):
    IPMatch = "IPMatch"
    ByteMatch = "ByteMatch"
    SqlInjectionMatch = "SqlInjectionMatch"
    GeoMatch = "GeoMatch"
    SizeConstraint = "SizeConstraint"
    XssMatch = "XssMatch"
    RegexMatch = "RegexMatch"


class RateKey(str):
    IP = "IP"


class TextTransformation(str):
    NONE = "NONE"
    COMPRESS_WHITE_SPACE = "COMPRESS_WHITE_SPACE"
    HTML_ENTITY_DECODE = "HTML_ENTITY_DECODE"
    LOWERCASE = "LOWERCASE"
    CMD_LINE = "CMD_LINE"
    URL_DECODE = "URL_DECODE"


class WafActionType(str):
    BLOCK = "BLOCK"
    ALLOW = "ALLOW"
    COUNT = "COUNT"


class WafOverrideActionType(str):
    NONE = "NONE"
    COUNT = "COUNT"


class WafRuleType(str):
    REGULAR = "REGULAR"
    RATE_BASED = "RATE_BASED"
    GROUP = "GROUP"


class WAFBadRequestException(ServiceException):
    message: Optional[errorMessage]


class WAFDisallowedNameException(ServiceException):
    message: Optional[errorMessage]


class WAFEntityMigrationException(ServiceException):
    message: Optional[errorMessage]
    MigrationErrorType: Optional[MigrationErrorType]
    MigrationErrorReason: Optional[ErrorReason]


class WAFInternalErrorException(ServiceException):
    message: Optional[errorMessage]


class WAFInvalidAccountException(ServiceException):
    pass


class WAFInvalidOperationException(ServiceException):
    message: Optional[errorMessage]


class WAFInvalidParameterException(ServiceException):
    field: Optional[ParameterExceptionField]
    parameter: Optional[ParameterExceptionParameter]
    reason: Optional[ParameterExceptionReason]


class WAFInvalidPermissionPolicyException(ServiceException):
    message: Optional[errorMessage]


class WAFInvalidRegexPatternException(ServiceException):
    message: Optional[errorMessage]


class WAFLimitsExceededException(ServiceException):
    message: Optional[errorMessage]


class WAFNonEmptyEntityException(ServiceException):
    message: Optional[errorMessage]


class WAFNonexistentContainerException(ServiceException):
    message: Optional[errorMessage]


class WAFNonexistentItemException(ServiceException):
    message: Optional[errorMessage]


class WAFReferencedItemException(ServiceException):
    message: Optional[errorMessage]


class WAFServiceLinkedRoleErrorException(ServiceException):
    message: Optional[errorMessage]


class WAFStaleDataException(ServiceException):
    message: Optional[errorMessage]


class WAFSubscriptionNotFoundException(ServiceException):
    message: Optional[errorMessage]


class WAFTagOperationException(ServiceException):
    message: Optional[errorMessage]


class WAFTagOperationInternalErrorException(ServiceException):
    message: Optional[errorMessage]


class ExcludedRule(TypedDict, total=False):
    RuleId: ResourceId


ExcludedRules = List[ExcludedRule]


class WafOverrideAction(TypedDict, total=False):
    Type: WafOverrideActionType


class WafAction(TypedDict, total=False):
    Type: WafActionType


class ActivatedRule(TypedDict, total=False):
    Priority: RulePriority
    RuleId: ResourceId
    Action: Optional[WafAction]
    OverrideAction: Optional[WafOverrideAction]
    Type: Optional[WafRuleType]
    ExcludedRules: Optional[ExcludedRules]


ActivatedRules = List[ActivatedRule]
ByteMatchTargetString = bytes


class FieldToMatch(TypedDict, total=False):
    Type: MatchFieldType
    Data: Optional[MatchFieldData]


class ByteMatchTuple(TypedDict, total=False):
    FieldToMatch: FieldToMatch
    TargetString: ByteMatchTargetString
    TextTransformation: TextTransformation
    PositionalConstraint: PositionalConstraint


ByteMatchTuples = List[ByteMatchTuple]


class ByteMatchSet(TypedDict, total=False):
    ByteMatchSetId: ResourceId
    Name: Optional[ResourceName]
    ByteMatchTuples: ByteMatchTuples


class ByteMatchSetSummary(TypedDict, total=False):
    ByteMatchSetId: ResourceId
    Name: ResourceName


ByteMatchSetSummaries = List[ByteMatchSetSummary]


class ByteMatchSetUpdate(TypedDict, total=False):
    Action: ChangeAction
    ByteMatchTuple: ByteMatchTuple


ByteMatchSetUpdates = List[ByteMatchSetUpdate]


class CreateByteMatchSetRequest(ServiceRequest):
    Name: ResourceName
    ChangeToken: ChangeToken


class CreateByteMatchSetResponse(TypedDict, total=False):
    ByteMatchSet: Optional[ByteMatchSet]
    ChangeToken: Optional[ChangeToken]


class CreateGeoMatchSetRequest(ServiceRequest):
    Name: ResourceName
    ChangeToken: ChangeToken


class GeoMatchConstraint(TypedDict, total=False):
    Type: GeoMatchConstraintType
    Value: GeoMatchConstraintValue


GeoMatchConstraints = List[GeoMatchConstraint]


class GeoMatchSet(TypedDict, total=False):
    GeoMatchSetId: ResourceId
    Name: Optional[ResourceName]
    GeoMatchConstraints: GeoMatchConstraints


class CreateGeoMatchSetResponse(TypedDict, total=False):
    GeoMatchSet: Optional[GeoMatchSet]
    ChangeToken: Optional[ChangeToken]


class CreateIPSetRequest(ServiceRequest):
    Name: ResourceName
    ChangeToken: ChangeToken


class IPSetDescriptor(TypedDict, total=False):
    Type: IPSetDescriptorType
    Value: IPSetDescriptorValue


IPSetDescriptors = List[IPSetDescriptor]


class IPSet(TypedDict, total=False):
    IPSetId: ResourceId
    Name: Optional[ResourceName]
    IPSetDescriptors: IPSetDescriptors


class CreateIPSetResponse(TypedDict, total=False):
    IPSet: Optional[IPSet]
    ChangeToken: Optional[ChangeToken]


class Tag(TypedDict, total=False):
    Key: TagKey
    Value: TagValue


TagList = List[Tag]
RateLimit = int


class CreateRateBasedRuleRequest(ServiceRequest):
    Name: ResourceName
    MetricName: MetricName
    RateKey: RateKey
    RateLimit: RateLimit
    ChangeToken: ChangeToken
    Tags: Optional[TagList]


class Predicate(TypedDict, total=False):
    Negated: Negated
    Type: PredicateType
    DataId: ResourceId


Predicates = List[Predicate]


class RateBasedRule(TypedDict, total=False):
    RuleId: ResourceId
    Name: Optional[ResourceName]
    MetricName: Optional[MetricName]
    MatchPredicates: Predicates
    RateKey: RateKey
    RateLimit: RateLimit


class CreateRateBasedRuleResponse(TypedDict, total=False):
    Rule: Optional[RateBasedRule]
    ChangeToken: Optional[ChangeToken]


class CreateRegexMatchSetRequest(ServiceRequest):
    Name: ResourceName
    ChangeToken: ChangeToken


class RegexMatchTuple(TypedDict, total=False):
    FieldToMatch: FieldToMatch
    TextTransformation: TextTransformation
    RegexPatternSetId: ResourceId


RegexMatchTuples = List[RegexMatchTuple]


class RegexMatchSet(TypedDict, total=False):
    RegexMatchSetId: Optional[ResourceId]
    Name: Optional[ResourceName]
    RegexMatchTuples: Optional[RegexMatchTuples]


class CreateRegexMatchSetResponse(TypedDict, total=False):
    RegexMatchSet: Optional[RegexMatchSet]
    ChangeToken: Optional[ChangeToken]


class CreateRegexPatternSetRequest(ServiceRequest):
    Name: ResourceName
    ChangeToken: ChangeToken


RegexPatternStrings = List[RegexPatternString]


class RegexPatternSet(TypedDict, total=False):
    RegexPatternSetId: ResourceId
    Name: Optional[ResourceName]
    RegexPatternStrings: RegexPatternStrings


class CreateRegexPatternSetResponse(TypedDict, total=False):
    RegexPatternSet: Optional[RegexPatternSet]
    ChangeToken: Optional[ChangeToken]


class CreateRuleGroupRequest(ServiceRequest):
    Name: ResourceName
    MetricName: MetricName
    ChangeToken: ChangeToken
    Tags: Optional[TagList]


class RuleGroup(TypedDict, total=False):
    RuleGroupId: ResourceId
    Name: Optional[ResourceName]
    MetricName: Optional[MetricName]


class CreateRuleGroupResponse(TypedDict, total=False):
    RuleGroup: Optional[RuleGroup]
    ChangeToken: Optional[ChangeToken]


class CreateRuleRequest(ServiceRequest):
    Name: ResourceName
    MetricName: MetricName
    ChangeToken: ChangeToken
    Tags: Optional[TagList]


class Rule(TypedDict, total=False):
    RuleId: ResourceId
    Name: Optional[ResourceName]
    MetricName: Optional[MetricName]
    Predicates: Predicates


class CreateRuleResponse(TypedDict, total=False):
    Rule: Optional[Rule]
    ChangeToken: Optional[ChangeToken]


class CreateSizeConstraintSetRequest(ServiceRequest):
    Name: ResourceName
    ChangeToken: ChangeToken


Size = int


class SizeConstraint(TypedDict, total=False):
    FieldToMatch: FieldToMatch
    TextTransformation: TextTransformation
    ComparisonOperator: ComparisonOperator
    Size: Size


SizeConstraints = List[SizeConstraint]


class SizeConstraintSet(TypedDict, total=False):
    SizeConstraintSetId: ResourceId
    Name: Optional[ResourceName]
    SizeConstraints: SizeConstraints


class CreateSizeConstraintSetResponse(TypedDict, total=False):
    SizeConstraintSet: Optional[SizeConstraintSet]
    ChangeToken: Optional[ChangeToken]


class CreateSqlInjectionMatchSetRequest(ServiceRequest):
    Name: ResourceName
    ChangeToken: ChangeToken


class SqlInjectionMatchTuple(TypedDict, total=False):
    FieldToMatch: FieldToMatch
    TextTransformation: TextTransformation


SqlInjectionMatchTuples = List[SqlInjectionMatchTuple]


class SqlInjectionMatchSet(TypedDict, total=False):
    SqlInjectionMatchSetId: ResourceId
    Name: Optional[ResourceName]
    SqlInjectionMatchTuples: SqlInjectionMatchTuples


class CreateSqlInjectionMatchSetResponse(TypedDict, total=False):
    SqlInjectionMatchSet: Optional[SqlInjectionMatchSet]
    ChangeToken: Optional[ChangeToken]


class CreateWebACLMigrationStackRequest(ServiceRequest):
    WebACLId: ResourceId
    S3BucketName: S3BucketName
    IgnoreUnsupportedType: IgnoreUnsupportedType


class CreateWebACLMigrationStackResponse(TypedDict, total=False):
    S3ObjectUrl: S3ObjectUrl


class CreateWebACLRequest(ServiceRequest):
    Name: ResourceName
    MetricName: MetricName
    DefaultAction: WafAction
    ChangeToken: ChangeToken
    Tags: Optional[TagList]


class WebACL(TypedDict, total=False):
    WebACLId: ResourceId
    Name: Optional[ResourceName]
    MetricName: Optional[MetricName]
    DefaultAction: WafAction
    Rules: ActivatedRules
    WebACLArn: Optional[ResourceArn]


class CreateWebACLResponse(TypedDict, total=False):
    WebACL: Optional[WebACL]
    ChangeToken: Optional[ChangeToken]


class CreateXssMatchSetRequest(ServiceRequest):
    Name: ResourceName
    ChangeToken: ChangeToken


class XssMatchTuple(TypedDict, total=False):
    FieldToMatch: FieldToMatch
    TextTransformation: TextTransformation


XssMatchTuples = List[XssMatchTuple]


class XssMatchSet(TypedDict, total=False):
    XssMatchSetId: ResourceId
    Name: Optional[ResourceName]
    XssMatchTuples: XssMatchTuples


class CreateXssMatchSetResponse(TypedDict, total=False):
    XssMatchSet: Optional[XssMatchSet]
    ChangeToken: Optional[ChangeToken]


class DeleteByteMatchSetRequest(ServiceRequest):
    ByteMatchSetId: ResourceId
    ChangeToken: ChangeToken


class DeleteByteMatchSetResponse(TypedDict, total=False):
    ChangeToken: Optional[ChangeToken]


class DeleteGeoMatchSetRequest(ServiceRequest):
    GeoMatchSetId: ResourceId
    ChangeToken: ChangeToken


class DeleteGeoMatchSetResponse(TypedDict, total=False):
    ChangeToken: Optional[ChangeToken]


class DeleteIPSetRequest(ServiceRequest):
    IPSetId: ResourceId
    ChangeToken: ChangeToken


class DeleteIPSetResponse(TypedDict, total=False):
    ChangeToken: Optional[ChangeToken]


class DeleteLoggingConfigurationRequest(ServiceRequest):
    ResourceArn: ResourceArn


class DeleteLoggingConfigurationResponse(TypedDict, total=False):
    pass


class DeletePermissionPolicyRequest(ServiceRequest):
    ResourceArn: ResourceArn


class DeletePermissionPolicyResponse(TypedDict, total=False):
    pass


class DeleteRateBasedRuleRequest(ServiceRequest):
    RuleId: ResourceId
    ChangeToken: ChangeToken


class DeleteRateBasedRuleResponse(TypedDict, total=False):
    ChangeToken: Optional[ChangeToken]


class DeleteRegexMatchSetRequest(ServiceRequest):
    RegexMatchSetId: ResourceId
    ChangeToken: ChangeToken


class DeleteRegexMatchSetResponse(TypedDict, total=False):
    ChangeToken: Optional[ChangeToken]


class DeleteRegexPatternSetRequest(ServiceRequest):
    RegexPatternSetId: ResourceId
    ChangeToken: ChangeToken


class DeleteRegexPatternSetResponse(TypedDict, total=False):
    ChangeToken: Optional[ChangeToken]


class DeleteRuleGroupRequest(ServiceRequest):
    RuleGroupId: ResourceId
    ChangeToken: ChangeToken


class DeleteRuleGroupResponse(TypedDict, total=False):
    ChangeToken: Optional[ChangeToken]


class DeleteRuleRequest(ServiceRequest):
    RuleId: ResourceId
    ChangeToken: ChangeToken


class DeleteRuleResponse(TypedDict, total=False):
    ChangeToken: Optional[ChangeToken]


class DeleteSizeConstraintSetRequest(ServiceRequest):
    SizeConstraintSetId: ResourceId
    ChangeToken: ChangeToken


class DeleteSizeConstraintSetResponse(TypedDict, total=False):
    ChangeToken: Optional[ChangeToken]


class DeleteSqlInjectionMatchSetRequest(ServiceRequest):
    SqlInjectionMatchSetId: ResourceId
    ChangeToken: ChangeToken


class DeleteSqlInjectionMatchSetResponse(TypedDict, total=False):
    ChangeToken: Optional[ChangeToken]


class DeleteWebACLRequest(ServiceRequest):
    WebACLId: ResourceId
    ChangeToken: ChangeToken


class DeleteWebACLResponse(TypedDict, total=False):
    ChangeToken: Optional[ChangeToken]


class DeleteXssMatchSetRequest(ServiceRequest):
    XssMatchSetId: ResourceId
    ChangeToken: ChangeToken


class DeleteXssMatchSetResponse(TypedDict, total=False):
    ChangeToken: Optional[ChangeToken]


class GeoMatchSetSummary(TypedDict, total=False):
    GeoMatchSetId: ResourceId
    Name: ResourceName


GeoMatchSetSummaries = List[GeoMatchSetSummary]


class GeoMatchSetUpdate(TypedDict, total=False):
    Action: ChangeAction
    GeoMatchConstraint: GeoMatchConstraint


GeoMatchSetUpdates = List[GeoMatchSetUpdate]


class GetByteMatchSetRequest(ServiceRequest):
    ByteMatchSetId: ResourceId


class GetByteMatchSetResponse(TypedDict, total=False):
    ByteMatchSet: Optional[ByteMatchSet]


class GetChangeTokenRequest(ServiceRequest):
    pass


class GetChangeTokenResponse(TypedDict, total=False):
    ChangeToken: Optional[ChangeToken]


class GetChangeTokenStatusRequest(ServiceRequest):
    ChangeToken: ChangeToken


class GetChangeTokenStatusResponse(TypedDict, total=False):
    ChangeTokenStatus: Optional[ChangeTokenStatus]


class GetGeoMatchSetRequest(ServiceRequest):
    GeoMatchSetId: ResourceId


class GetGeoMatchSetResponse(TypedDict, total=False):
    GeoMatchSet: Optional[GeoMatchSet]


class GetIPSetRequest(ServiceRequest):
    IPSetId: ResourceId


class GetIPSetResponse(TypedDict, total=False):
    IPSet: Optional[IPSet]


class GetLoggingConfigurationRequest(ServiceRequest):
    ResourceArn: ResourceArn


RedactedFields = List[FieldToMatch]
LogDestinationConfigs = List[ResourceArn]


class LoggingConfiguration(TypedDict, total=False):
    ResourceArn: ResourceArn
    LogDestinationConfigs: LogDestinationConfigs
    RedactedFields: Optional[RedactedFields]


class GetLoggingConfigurationResponse(TypedDict, total=False):
    LoggingConfiguration: Optional[LoggingConfiguration]


class GetPermissionPolicyRequest(ServiceRequest):
    ResourceArn: ResourceArn


class GetPermissionPolicyResponse(TypedDict, total=False):
    Policy: Optional[PolicyString]


class GetRateBasedRuleManagedKeysRequest(ServiceRequest):
    RuleId: ResourceId
    NextMarker: Optional[NextMarker]


ManagedKeys = List[ManagedKey]


class GetRateBasedRuleManagedKeysResponse(TypedDict, total=False):
    ManagedKeys: Optional[ManagedKeys]
    NextMarker: Optional[NextMarker]


class GetRateBasedRuleRequest(ServiceRequest):
    RuleId: ResourceId


class GetRateBasedRuleResponse(TypedDict, total=False):
    Rule: Optional[RateBasedRule]


class GetRegexMatchSetRequest(ServiceRequest):
    RegexMatchSetId: ResourceId


class GetRegexMatchSetResponse(TypedDict, total=False):
    RegexMatchSet: Optional[RegexMatchSet]


class GetRegexPatternSetRequest(ServiceRequest):
    RegexPatternSetId: ResourceId


class GetRegexPatternSetResponse(TypedDict, total=False):
    RegexPatternSet: Optional[RegexPatternSet]


class GetRuleGroupRequest(ServiceRequest):
    RuleGroupId: ResourceId


class GetRuleGroupResponse(TypedDict, total=False):
    RuleGroup: Optional[RuleGroup]


class GetRuleRequest(ServiceRequest):
    RuleId: ResourceId


class GetRuleResponse(TypedDict, total=False):
    Rule: Optional[Rule]


GetSampledRequestsMaxItems = int
Timestamp = datetime


class TimeWindow(TypedDict, total=False):
    StartTime: Timestamp
    EndTime: Timestamp


class GetSampledRequestsRequest(ServiceRequest):
    WebAclId: ResourceId
    RuleId: ResourceId
    TimeWindow: TimeWindow
    MaxItems: GetSampledRequestsMaxItems


PopulationSize = int
SampleWeight = int


class HTTPHeader(TypedDict, total=False):
    Name: Optional[HeaderName]
    Value: Optional[HeaderValue]


HTTPHeaders = List[HTTPHeader]


class HTTPRequest(TypedDict, total=False):
    ClientIP: Optional[IPString]
    Country: Optional[Country]
    URI: Optional[URIString]
    Method: Optional[HTTPMethod]
    HTTPVersion: Optional[HTTPVersion]
    Headers: Optional[HTTPHeaders]


class SampledHTTPRequest(TypedDict, total=False):
    Request: HTTPRequest
    Weight: SampleWeight
    Timestamp: Optional[Timestamp]
    Action: Optional[Action]
    RuleWithinRuleGroup: Optional[ResourceId]


SampledHTTPRequests = List[SampledHTTPRequest]


class GetSampledRequestsResponse(TypedDict, total=False):
    SampledRequests: Optional[SampledHTTPRequests]
    PopulationSize: Optional[PopulationSize]
    TimeWindow: Optional[TimeWindow]


class GetSizeConstraintSetRequest(ServiceRequest):
    SizeConstraintSetId: ResourceId


class GetSizeConstraintSetResponse(TypedDict, total=False):
    SizeConstraintSet: Optional[SizeConstraintSet]


class GetSqlInjectionMatchSetRequest(ServiceRequest):
    SqlInjectionMatchSetId: ResourceId


class GetSqlInjectionMatchSetResponse(TypedDict, total=False):
    SqlInjectionMatchSet: Optional[SqlInjectionMatchSet]


class GetWebACLRequest(ServiceRequest):
    WebACLId: ResourceId


class GetWebACLResponse(TypedDict, total=False):
    WebACL: Optional[WebACL]


class GetXssMatchSetRequest(ServiceRequest):
    XssMatchSetId: ResourceId


class GetXssMatchSetResponse(TypedDict, total=False):
    XssMatchSet: Optional[XssMatchSet]


class IPSetSummary(TypedDict, total=False):
    IPSetId: ResourceId
    Name: ResourceName


IPSetSummaries = List[IPSetSummary]


class IPSetUpdate(TypedDict, total=False):
    Action: ChangeAction
    IPSetDescriptor: IPSetDescriptor


IPSetUpdates = List[IPSetUpdate]


class ListActivatedRulesInRuleGroupRequest(ServiceRequest):
    RuleGroupId: Optional[ResourceId]
    NextMarker: Optional[NextMarker]
    Limit: Optional[PaginationLimit]


class ListActivatedRulesInRuleGroupResponse(TypedDict, total=False):
    NextMarker: Optional[NextMarker]
    ActivatedRules: Optional[ActivatedRules]


class ListByteMatchSetsRequest(ServiceRequest):
    NextMarker: Optional[NextMarker]
    Limit: Optional[PaginationLimit]


class ListByteMatchSetsResponse(TypedDict, total=False):
    NextMarker: Optional[NextMarker]
    ByteMatchSets: Optional[ByteMatchSetSummaries]


class ListGeoMatchSetsRequest(ServiceRequest):
    NextMarker: Optional[NextMarker]
    Limit: Optional[PaginationLimit]


class ListGeoMatchSetsResponse(TypedDict, total=False):
    NextMarker: Optional[NextMarker]
    GeoMatchSets: Optional[GeoMatchSetSummaries]


class ListIPSetsRequest(ServiceRequest):
    NextMarker: Optional[NextMarker]
    Limit: Optional[PaginationLimit]


class ListIPSetsResponse(TypedDict, total=False):
    NextMarker: Optional[NextMarker]
    IPSets: Optional[IPSetSummaries]


class ListLoggingConfigurationsRequest(ServiceRequest):
    NextMarker: Optional[NextMarker]
    Limit: Optional[PaginationLimit]


LoggingConfigurations = List[LoggingConfiguration]


class ListLoggingConfigurationsResponse(TypedDict, total=False):
    LoggingConfigurations: Optional[LoggingConfigurations]
    NextMarker: Optional[NextMarker]


class ListRateBasedRulesRequest(ServiceRequest):
    NextMarker: Optional[NextMarker]
    Limit: Optional[PaginationLimit]


class RuleSummary(TypedDict, total=False):
    RuleId: ResourceId
    Name: ResourceName


RuleSummaries = List[RuleSummary]


class ListRateBasedRulesResponse(TypedDict, total=False):
    NextMarker: Optional[NextMarker]
    Rules: Optional[RuleSummaries]


class ListRegexMatchSetsRequest(ServiceRequest):
    NextMarker: Optional[NextMarker]
    Limit: Optional[PaginationLimit]


class RegexMatchSetSummary(TypedDict, total=False):
    RegexMatchSetId: ResourceId
    Name: ResourceName


RegexMatchSetSummaries = List[RegexMatchSetSummary]


class ListRegexMatchSetsResponse(TypedDict, total=False):
    NextMarker: Optional[NextMarker]
    RegexMatchSets: Optional[RegexMatchSetSummaries]


class ListRegexPatternSetsRequest(ServiceRequest):
    NextMarker: Optional[NextMarker]
    Limit: Optional[PaginationLimit]


class RegexPatternSetSummary(TypedDict, total=False):
    RegexPatternSetId: ResourceId
    Name: ResourceName


RegexPatternSetSummaries = List[RegexPatternSetSummary]


class ListRegexPatternSetsResponse(TypedDict, total=False):
    NextMarker: Optional[NextMarker]
    RegexPatternSets: Optional[RegexPatternSetSummaries]


class ListRuleGroupsRequest(ServiceRequest):
    NextMarker: Optional[NextMarker]
    Limit: Optional[PaginationLimit]


class RuleGroupSummary(TypedDict, total=False):
    RuleGroupId: ResourceId
    Name: ResourceName


RuleGroupSummaries = List[RuleGroupSummary]


class ListRuleGroupsResponse(TypedDict, total=False):
    NextMarker: Optional[NextMarker]
    RuleGroups: Optional[RuleGroupSummaries]


class ListRulesRequest(ServiceRequest):
    NextMarker: Optional[NextMarker]
    Limit: Optional[PaginationLimit]


class ListRulesResponse(TypedDict, total=False):
    NextMarker: Optional[NextMarker]
    Rules: Optional[RuleSummaries]


class ListSizeConstraintSetsRequest(ServiceRequest):
    NextMarker: Optional[NextMarker]
    Limit: Optional[PaginationLimit]


class SizeConstraintSetSummary(TypedDict, total=False):
    SizeConstraintSetId: ResourceId
    Name: ResourceName


SizeConstraintSetSummaries = List[SizeConstraintSetSummary]


class ListSizeConstraintSetsResponse(TypedDict, total=False):
    NextMarker: Optional[NextMarker]
    SizeConstraintSets: Optional[SizeConstraintSetSummaries]


class ListSqlInjectionMatchSetsRequest(ServiceRequest):
    NextMarker: Optional[NextMarker]
    Limit: Optional[PaginationLimit]


class SqlInjectionMatchSetSummary(TypedDict, total=False):
    SqlInjectionMatchSetId: ResourceId
    Name: ResourceName


SqlInjectionMatchSetSummaries = List[SqlInjectionMatchSetSummary]


class ListSqlInjectionMatchSetsResponse(TypedDict, total=False):
    NextMarker: Optional[NextMarker]
    SqlInjectionMatchSets: Optional[SqlInjectionMatchSetSummaries]


class ListSubscribedRuleGroupsRequest(ServiceRequest):
    NextMarker: Optional[NextMarker]
    Limit: Optional[PaginationLimit]


class SubscribedRuleGroupSummary(TypedDict, total=False):
    RuleGroupId: ResourceId
    Name: ResourceName
    MetricName: MetricName


SubscribedRuleGroupSummaries = List[SubscribedRuleGroupSummary]


class ListSubscribedRuleGroupsResponse(TypedDict, total=False):
    NextMarker: Optional[NextMarker]
    RuleGroups: Optional[SubscribedRuleGroupSummaries]


class ListTagsForResourceRequest(ServiceRequest):
    NextMarker: Optional[NextMarker]
    Limit: Optional[PaginationLimit]
    ResourceARN: ResourceArn


class TagInfoForResource(TypedDict, total=False):
    ResourceARN: Optional[ResourceArn]
    TagList: Optional[TagList]


class ListTagsForResourceResponse(TypedDict, total=False):
    NextMarker: Optional[NextMarker]
    TagInfoForResource: Optional[TagInfoForResource]


class ListWebACLsRequest(ServiceRequest):
    NextMarker: Optional[NextMarker]
    Limit: Optional[PaginationLimit]


class WebACLSummary(TypedDict, total=False):
    WebACLId: ResourceId
    Name: ResourceName


WebACLSummaries = List[WebACLSummary]


class ListWebACLsResponse(TypedDict, total=False):
    NextMarker: Optional[NextMarker]
    WebACLs: Optional[WebACLSummaries]


class ListXssMatchSetsRequest(ServiceRequest):
    NextMarker: Optional[NextMarker]
    Limit: Optional[PaginationLimit]


class XssMatchSetSummary(TypedDict, total=False):
    XssMatchSetId: ResourceId
    Name: ResourceName


XssMatchSetSummaries = List[XssMatchSetSummary]


class ListXssMatchSetsResponse(TypedDict, total=False):
    NextMarker: Optional[NextMarker]
    XssMatchSets: Optional[XssMatchSetSummaries]


class PutLoggingConfigurationRequest(ServiceRequest):
    LoggingConfiguration: LoggingConfiguration


class PutLoggingConfigurationResponse(TypedDict, total=False):
    LoggingConfiguration: Optional[LoggingConfiguration]


class PutPermissionPolicyRequest(ServiceRequest):
    ResourceArn: ResourceArn
    Policy: PolicyString


class PutPermissionPolicyResponse(TypedDict, total=False):
    pass


class RegexMatchSetUpdate(TypedDict, total=False):
    Action: ChangeAction
    RegexMatchTuple: RegexMatchTuple


RegexMatchSetUpdates = List[RegexMatchSetUpdate]


class RegexPatternSetUpdate(TypedDict, total=False):
    Action: ChangeAction
    RegexPatternString: RegexPatternString


RegexPatternSetUpdates = List[RegexPatternSetUpdate]


class RuleGroupUpdate(TypedDict, total=False):
    Action: ChangeAction
    ActivatedRule: ActivatedRule


RuleGroupUpdates = List[RuleGroupUpdate]


class RuleUpdate(TypedDict, total=False):
    Action: ChangeAction
    Predicate: Predicate


RuleUpdates = List[RuleUpdate]


class SizeConstraintSetUpdate(TypedDict, total=False):
    Action: ChangeAction
    SizeConstraint: SizeConstraint


SizeConstraintSetUpdates = List[SizeConstraintSetUpdate]


class SqlInjectionMatchSetUpdate(TypedDict, total=False):
    Action: ChangeAction
    SqlInjectionMatchTuple: SqlInjectionMatchTuple


SqlInjectionMatchSetUpdates = List[SqlInjectionMatchSetUpdate]
TagKeyList = List[TagKey]


class TagResourceRequest(ServiceRequest):
    ResourceARN: ResourceArn
    Tags: TagList


class TagResourceResponse(TypedDict, total=False):
    pass


class UntagResourceRequest(ServiceRequest):
    ResourceARN: ResourceArn
    TagKeys: TagKeyList


class UntagResourceResponse(TypedDict, total=False):
    pass


class UpdateByteMatchSetRequest(ServiceRequest):
    ByteMatchSetId: ResourceId
    ChangeToken: ChangeToken
    Updates: ByteMatchSetUpdates


class UpdateByteMatchSetResponse(TypedDict, total=False):
    ChangeToken: Optional[ChangeToken]


class UpdateGeoMatchSetRequest(ServiceRequest):
    GeoMatchSetId: ResourceId
    ChangeToken: ChangeToken
    Updates: GeoMatchSetUpdates


class UpdateGeoMatchSetResponse(TypedDict, total=False):
    ChangeToken: Optional[ChangeToken]


class UpdateIPSetRequest(ServiceRequest):
    IPSetId: ResourceId
    ChangeToken: ChangeToken
    Updates: IPSetUpdates


class UpdateIPSetResponse(TypedDict, total=False):
    ChangeToken: Optional[ChangeToken]


class UpdateRateBasedRuleRequest(ServiceRequest):
    RuleId: ResourceId
    ChangeToken: ChangeToken
    Updates: RuleUpdates
    RateLimit: RateLimit


class UpdateRateBasedRuleResponse(TypedDict, total=False):
    ChangeToken: Optional[ChangeToken]


class UpdateRegexMatchSetRequest(ServiceRequest):
    RegexMatchSetId: ResourceId
    Updates: RegexMatchSetUpdates
    ChangeToken: ChangeToken


class UpdateRegexMatchSetResponse(TypedDict, total=False):
    ChangeToken: Optional[ChangeToken]


class UpdateRegexPatternSetRequest(ServiceRequest):
    RegexPatternSetId: ResourceId
    Updates: RegexPatternSetUpdates
    ChangeToken: ChangeToken


class UpdateRegexPatternSetResponse(TypedDict, total=False):
    ChangeToken: Optional[ChangeToken]


class UpdateRuleGroupRequest(ServiceRequest):
    RuleGroupId: ResourceId
    Updates: RuleGroupUpdates
    ChangeToken: ChangeToken


class UpdateRuleGroupResponse(TypedDict, total=False):
    ChangeToken: Optional[ChangeToken]


class UpdateRuleRequest(ServiceRequest):
    RuleId: ResourceId
    ChangeToken: ChangeToken
    Updates: RuleUpdates


class UpdateRuleResponse(TypedDict, total=False):
    ChangeToken: Optional[ChangeToken]


class UpdateSizeConstraintSetRequest(ServiceRequest):
    SizeConstraintSetId: ResourceId
    ChangeToken: ChangeToken
    Updates: SizeConstraintSetUpdates


class UpdateSizeConstraintSetResponse(TypedDict, total=False):
    ChangeToken: Optional[ChangeToken]


class UpdateSqlInjectionMatchSetRequest(ServiceRequest):
    SqlInjectionMatchSetId: ResourceId
    ChangeToken: ChangeToken
    Updates: SqlInjectionMatchSetUpdates


class UpdateSqlInjectionMatchSetResponse(TypedDict, total=False):
    ChangeToken: Optional[ChangeToken]


class WebACLUpdate(TypedDict, total=False):
    Action: ChangeAction
    ActivatedRule: ActivatedRule


WebACLUpdates = List[WebACLUpdate]


class UpdateWebACLRequest(ServiceRequest):
    WebACLId: ResourceId
    ChangeToken: ChangeToken
    Updates: Optional[WebACLUpdates]
    DefaultAction: Optional[WafAction]


class UpdateWebACLResponse(TypedDict, total=False):
    ChangeToken: Optional[ChangeToken]


class XssMatchSetUpdate(TypedDict, total=False):
    Action: ChangeAction
    XssMatchTuple: XssMatchTuple


XssMatchSetUpdates = List[XssMatchSetUpdate]


class UpdateXssMatchSetRequest(ServiceRequest):
    XssMatchSetId: ResourceId
    ChangeToken: ChangeToken
    Updates: XssMatchSetUpdates


class UpdateXssMatchSetResponse(TypedDict, total=False):
    ChangeToken: Optional[ChangeToken]


class WafApi:

    service = "waf"
    version = "2015-08-24"

    @handler("CreateByteMatchSet")
    def create_byte_match_set(
        self, context: RequestContext, name: ResourceName, change_token: ChangeToken
    ) -> CreateByteMatchSetResponse:
        raise NotImplementedError

    @handler("CreateGeoMatchSet")
    def create_geo_match_set(
        self, context: RequestContext, name: ResourceName, change_token: ChangeToken
    ) -> CreateGeoMatchSetResponse:
        raise NotImplementedError

    @handler("CreateIPSet")
    def create_ip_set(
        self, context: RequestContext, name: ResourceName, change_token: ChangeToken
    ) -> CreateIPSetResponse:
        raise NotImplementedError

    @handler("CreateRateBasedRule")
    def create_rate_based_rule(
        self,
        context: RequestContext,
        name: ResourceName,
        metric_name: MetricName,
        rate_key: RateKey,
        rate_limit: RateLimit,
        change_token: ChangeToken,
        tags: TagList = None,
    ) -> CreateRateBasedRuleResponse:
        raise NotImplementedError

    @handler("CreateRegexMatchSet")
    def create_regex_match_set(
        self, context: RequestContext, name: ResourceName, change_token: ChangeToken
    ) -> CreateRegexMatchSetResponse:
        raise NotImplementedError

    @handler("CreateRegexPatternSet")
    def create_regex_pattern_set(
        self, context: RequestContext, name: ResourceName, change_token: ChangeToken
    ) -> CreateRegexPatternSetResponse:
        raise NotImplementedError

    @handler("CreateRule")
    def create_rule(
        self,
        context: RequestContext,
        name: ResourceName,
        metric_name: MetricName,
        change_token: ChangeToken,
        tags: TagList = None,
    ) -> CreateRuleResponse:
        raise NotImplementedError

    @handler("CreateRuleGroup")
    def create_rule_group(
        self,
        context: RequestContext,
        name: ResourceName,
        metric_name: MetricName,
        change_token: ChangeToken,
        tags: TagList = None,
    ) -> CreateRuleGroupResponse:
        raise NotImplementedError

    @handler("CreateSizeConstraintSet")
    def create_size_constraint_set(
        self, context: RequestContext, name: ResourceName, change_token: ChangeToken
    ) -> CreateSizeConstraintSetResponse:
        raise NotImplementedError

    @handler("CreateSqlInjectionMatchSet")
    def create_sql_injection_match_set(
        self, context: RequestContext, name: ResourceName, change_token: ChangeToken
    ) -> CreateSqlInjectionMatchSetResponse:
        raise NotImplementedError

    @handler("CreateWebACL")
    def create_web_acl(
        self,
        context: RequestContext,
        name: ResourceName,
        metric_name: MetricName,
        default_action: WafAction,
        change_token: ChangeToken,
        tags: TagList = None,
    ) -> CreateWebACLResponse:
        raise NotImplementedError

    @handler("CreateWebACLMigrationStack")
    def create_web_acl_migration_stack(
        self,
        context: RequestContext,
        web_acl_id: ResourceId,
        s3_bucket_name: S3BucketName,
        ignore_unsupported_type: IgnoreUnsupportedType,
    ) -> CreateWebACLMigrationStackResponse:
        raise NotImplementedError

    @handler("CreateXssMatchSet")
    def create_xss_match_set(
        self, context: RequestContext, name: ResourceName, change_token: ChangeToken
    ) -> CreateXssMatchSetResponse:
        raise NotImplementedError

    @handler("DeleteByteMatchSet")
    def delete_byte_match_set(
        self, context: RequestContext, byte_match_set_id: ResourceId, change_token: ChangeToken
    ) -> DeleteByteMatchSetResponse:
        raise NotImplementedError

    @handler("DeleteGeoMatchSet")
    def delete_geo_match_set(
        self, context: RequestContext, geo_match_set_id: ResourceId, change_token: ChangeToken
    ) -> DeleteGeoMatchSetResponse:
        raise NotImplementedError

    @handler("DeleteIPSet")
    def delete_ip_set(
        self, context: RequestContext, ip_set_id: ResourceId, change_token: ChangeToken
    ) -> DeleteIPSetResponse:
        raise NotImplementedError

    @handler("DeleteLoggingConfiguration")
    def delete_logging_configuration(
        self, context: RequestContext, resource_arn: ResourceArn
    ) -> DeleteLoggingConfigurationResponse:
        raise NotImplementedError

    @handler("DeletePermissionPolicy")
    def delete_permission_policy(
        self, context: RequestContext, resource_arn: ResourceArn
    ) -> DeletePermissionPolicyResponse:
        raise NotImplementedError

    @handler("DeleteRateBasedRule")
    def delete_rate_based_rule(
        self, context: RequestContext, rule_id: ResourceId, change_token: ChangeToken
    ) -> DeleteRateBasedRuleResponse:
        raise NotImplementedError

    @handler("DeleteRegexMatchSet")
    def delete_regex_match_set(
        self, context: RequestContext, regex_match_set_id: ResourceId, change_token: ChangeToken
    ) -> DeleteRegexMatchSetResponse:
        raise NotImplementedError

    @handler("DeleteRegexPatternSet")
    def delete_regex_pattern_set(
        self, context: RequestContext, regex_pattern_set_id: ResourceId, change_token: ChangeToken
    ) -> DeleteRegexPatternSetResponse:
        raise NotImplementedError

    @handler("DeleteRule")
    def delete_rule(
        self, context: RequestContext, rule_id: ResourceId, change_token: ChangeToken
    ) -> DeleteRuleResponse:
        raise NotImplementedError

    @handler("DeleteRuleGroup")
    def delete_rule_group(
        self, context: RequestContext, rule_group_id: ResourceId, change_token: ChangeToken
    ) -> DeleteRuleGroupResponse:
        raise NotImplementedError

    @handler("DeleteSizeConstraintSet")
    def delete_size_constraint_set(
        self, context: RequestContext, size_constraint_set_id: ResourceId, change_token: ChangeToken
    ) -> DeleteSizeConstraintSetResponse:
        raise NotImplementedError

    @handler("DeleteSqlInjectionMatchSet")
    def delete_sql_injection_match_set(
        self,
        context: RequestContext,
        sql_injection_match_set_id: ResourceId,
        change_token: ChangeToken,
    ) -> DeleteSqlInjectionMatchSetResponse:
        raise NotImplementedError

    @handler("DeleteWebACL")
    def delete_web_acl(
        self, context: RequestContext, web_acl_id: ResourceId, change_token: ChangeToken
    ) -> DeleteWebACLResponse:
        raise NotImplementedError

    @handler("DeleteXssMatchSet")
    def delete_xss_match_set(
        self, context: RequestContext, xss_match_set_id: ResourceId, change_token: ChangeToken
    ) -> DeleteXssMatchSetResponse:
        raise NotImplementedError

    @handler("GetByteMatchSet")
    def get_byte_match_set(
        self, context: RequestContext, byte_match_set_id: ResourceId
    ) -> GetByteMatchSetResponse:
        raise NotImplementedError

    @handler("GetChangeToken")
    def get_change_token(
        self,
        context: RequestContext,
    ) -> GetChangeTokenResponse:
        raise NotImplementedError

    @handler("GetChangeTokenStatus")
    def get_change_token_status(
        self, context: RequestContext, change_token: ChangeToken
    ) -> GetChangeTokenStatusResponse:
        raise NotImplementedError

    @handler("GetGeoMatchSet")
    def get_geo_match_set(
        self, context: RequestContext, geo_match_set_id: ResourceId
    ) -> GetGeoMatchSetResponse:
        raise NotImplementedError

    @handler("GetIPSet")
    def get_ip_set(self, context: RequestContext, ip_set_id: ResourceId) -> GetIPSetResponse:
        raise NotImplementedError

    @handler("GetLoggingConfiguration")
    def get_logging_configuration(
        self, context: RequestContext, resource_arn: ResourceArn
    ) -> GetLoggingConfigurationResponse:
        raise NotImplementedError

    @handler("GetPermissionPolicy")
    def get_permission_policy(
        self, context: RequestContext, resource_arn: ResourceArn
    ) -> GetPermissionPolicyResponse:
        raise NotImplementedError

    @handler("GetRateBasedRule")
    def get_rate_based_rule(
        self, context: RequestContext, rule_id: ResourceId
    ) -> GetRateBasedRuleResponse:
        raise NotImplementedError

    @handler("GetRateBasedRuleManagedKeys")
    def get_rate_based_rule_managed_keys(
        self, context: RequestContext, rule_id: ResourceId, next_marker: NextMarker = None
    ) -> GetRateBasedRuleManagedKeysResponse:
        raise NotImplementedError

    @handler("GetRegexMatchSet")
    def get_regex_match_set(
        self, context: RequestContext, regex_match_set_id: ResourceId
    ) -> GetRegexMatchSetResponse:
        raise NotImplementedError

    @handler("GetRegexPatternSet")
    def get_regex_pattern_set(
        self, context: RequestContext, regex_pattern_set_id: ResourceId
    ) -> GetRegexPatternSetResponse:
        raise NotImplementedError

    @handler("GetRule")
    def get_rule(self, context: RequestContext, rule_id: ResourceId) -> GetRuleResponse:
        raise NotImplementedError

    @handler("GetRuleGroup")
    def get_rule_group(
        self, context: RequestContext, rule_group_id: ResourceId
    ) -> GetRuleGroupResponse:
        raise NotImplementedError

    @handler("GetSampledRequests")
    def get_sampled_requests(
        self,
        context: RequestContext,
        web_acl_id: ResourceId,
        rule_id: ResourceId,
        time_window: TimeWindow,
        max_items: GetSampledRequestsMaxItems,
    ) -> GetSampledRequestsResponse:
        raise NotImplementedError

    @handler("GetSizeConstraintSet")
    def get_size_constraint_set(
        self, context: RequestContext, size_constraint_set_id: ResourceId
    ) -> GetSizeConstraintSetResponse:
        raise NotImplementedError

    @handler("GetSqlInjectionMatchSet")
    def get_sql_injection_match_set(
        self, context: RequestContext, sql_injection_match_set_id: ResourceId
    ) -> GetSqlInjectionMatchSetResponse:
        raise NotImplementedError

    @handler("GetWebACL")
    def get_web_acl(self, context: RequestContext, web_acl_id: ResourceId) -> GetWebACLResponse:
        raise NotImplementedError

    @handler("GetXssMatchSet")
    def get_xss_match_set(
        self, context: RequestContext, xss_match_set_id: ResourceId
    ) -> GetXssMatchSetResponse:
        raise NotImplementedError

    @handler("ListActivatedRulesInRuleGroup")
    def list_activated_rules_in_rule_group(
        self,
        context: RequestContext,
        rule_group_id: ResourceId = None,
        next_marker: NextMarker = None,
        limit: PaginationLimit = None,
    ) -> ListActivatedRulesInRuleGroupResponse:
        raise NotImplementedError

    @handler("ListByteMatchSets")
    def list_byte_match_sets(
        self, context: RequestContext, next_marker: NextMarker = None, limit: PaginationLimit = None
    ) -> ListByteMatchSetsResponse:
        raise NotImplementedError

    @handler("ListGeoMatchSets")
    def list_geo_match_sets(
        self, context: RequestContext, next_marker: NextMarker = None, limit: PaginationLimit = None
    ) -> ListGeoMatchSetsResponse:
        raise NotImplementedError

    @handler("ListIPSets")
    def list_ip_sets(
        self, context: RequestContext, next_marker: NextMarker = None, limit: PaginationLimit = None
    ) -> ListIPSetsResponse:
        raise NotImplementedError

    @handler("ListLoggingConfigurations")
    def list_logging_configurations(
        self, context: RequestContext, next_marker: NextMarker = None, limit: PaginationLimit = None
    ) -> ListLoggingConfigurationsResponse:
        raise NotImplementedError

    @handler("ListRateBasedRules")
    def list_rate_based_rules(
        self, context: RequestContext, next_marker: NextMarker = None, limit: PaginationLimit = None
    ) -> ListRateBasedRulesResponse:
        raise NotImplementedError

    @handler("ListRegexMatchSets")
    def list_regex_match_sets(
        self, context: RequestContext, next_marker: NextMarker = None, limit: PaginationLimit = None
    ) -> ListRegexMatchSetsResponse:
        raise NotImplementedError

    @handler("ListRegexPatternSets")
    def list_regex_pattern_sets(
        self, context: RequestContext, next_marker: NextMarker = None, limit: PaginationLimit = None
    ) -> ListRegexPatternSetsResponse:
        raise NotImplementedError

    @handler("ListRuleGroups")
    def list_rule_groups(
        self, context: RequestContext, next_marker: NextMarker = None, limit: PaginationLimit = None
    ) -> ListRuleGroupsResponse:
        raise NotImplementedError

    @handler("ListRules")
    def list_rules(
        self, context: RequestContext, next_marker: NextMarker = None, limit: PaginationLimit = None
    ) -> ListRulesResponse:
        raise NotImplementedError

    @handler("ListSizeConstraintSets")
    def list_size_constraint_sets(
        self, context: RequestContext, next_marker: NextMarker = None, limit: PaginationLimit = None
    ) -> ListSizeConstraintSetsResponse:
        raise NotImplementedError

    @handler("ListSqlInjectionMatchSets")
    def list_sql_injection_match_sets(
        self, context: RequestContext, next_marker: NextMarker = None, limit: PaginationLimit = None
    ) -> ListSqlInjectionMatchSetsResponse:
        raise NotImplementedError

    @handler("ListSubscribedRuleGroups")
    def list_subscribed_rule_groups(
        self, context: RequestContext, next_marker: NextMarker = None, limit: PaginationLimit = None
    ) -> ListSubscribedRuleGroupsResponse:
        raise NotImplementedError

    @handler("ListTagsForResource")
    def list_tags_for_resource(
        self,
        context: RequestContext,
        resource_arn: ResourceArn,
        next_marker: NextMarker = None,
        limit: PaginationLimit = None,
    ) -> ListTagsForResourceResponse:
        raise NotImplementedError

    @handler("ListWebACLs")
    def list_web_ac_ls(
        self, context: RequestContext, next_marker: NextMarker = None, limit: PaginationLimit = None
    ) -> ListWebACLsResponse:
        raise NotImplementedError

    @handler("ListXssMatchSets")
    def list_xss_match_sets(
        self, context: RequestContext, next_marker: NextMarker = None, limit: PaginationLimit = None
    ) -> ListXssMatchSetsResponse:
        raise NotImplementedError

    @handler("PutLoggingConfiguration")
    def put_logging_configuration(
        self, context: RequestContext, logging_configuration: LoggingConfiguration
    ) -> PutLoggingConfigurationResponse:
        raise NotImplementedError

    @handler("PutPermissionPolicy")
    def put_permission_policy(
        self, context: RequestContext, resource_arn: ResourceArn, policy: PolicyString
    ) -> PutPermissionPolicyResponse:
        raise NotImplementedError

    @handler("TagResource")
    def tag_resource(
        self, context: RequestContext, resource_arn: ResourceArn, tags: TagList
    ) -> TagResourceResponse:
        raise NotImplementedError

    @handler("UntagResource")
    def untag_resource(
        self, context: RequestContext, resource_arn: ResourceArn, tag_keys: TagKeyList
    ) -> UntagResourceResponse:
        raise NotImplementedError

    @handler("UpdateByteMatchSet")
    def update_byte_match_set(
        self,
        context: RequestContext,
        byte_match_set_id: ResourceId,
        change_token: ChangeToken,
        updates: ByteMatchSetUpdates,
    ) -> UpdateByteMatchSetResponse:
        raise NotImplementedError

    @handler("UpdateGeoMatchSet")
    def update_geo_match_set(
        self,
        context: RequestContext,
        geo_match_set_id: ResourceId,
        change_token: ChangeToken,
        updates: GeoMatchSetUpdates,
    ) -> UpdateGeoMatchSetResponse:
        raise NotImplementedError

    @handler("UpdateIPSet")
    def update_ip_set(
        self,
        context: RequestContext,
        ip_set_id: ResourceId,
        change_token: ChangeToken,
        updates: IPSetUpdates,
    ) -> UpdateIPSetResponse:
        raise NotImplementedError

    @handler("UpdateRateBasedRule")
    def update_rate_based_rule(
        self,
        context: RequestContext,
        rule_id: ResourceId,
        change_token: ChangeToken,
        updates: RuleUpdates,
        rate_limit: RateLimit,
    ) -> UpdateRateBasedRuleResponse:
        raise NotImplementedError

    @handler("UpdateRegexMatchSet")
    def update_regex_match_set(
        self,
        context: RequestContext,
        regex_match_set_id: ResourceId,
        updates: RegexMatchSetUpdates,
        change_token: ChangeToken,
    ) -> UpdateRegexMatchSetResponse:
        raise NotImplementedError

    @handler("UpdateRegexPatternSet")
    def update_regex_pattern_set(
        self,
        context: RequestContext,
        regex_pattern_set_id: ResourceId,
        updates: RegexPatternSetUpdates,
        change_token: ChangeToken,
    ) -> UpdateRegexPatternSetResponse:
        raise NotImplementedError

    @handler("UpdateRule")
    def update_rule(
        self,
        context: RequestContext,
        rule_id: ResourceId,
        change_token: ChangeToken,
        updates: RuleUpdates,
    ) -> UpdateRuleResponse:
        raise NotImplementedError

    @handler("UpdateRuleGroup")
    def update_rule_group(
        self,
        context: RequestContext,
        rule_group_id: ResourceId,
        updates: RuleGroupUpdates,
        change_token: ChangeToken,
    ) -> UpdateRuleGroupResponse:
        raise NotImplementedError

    @handler("UpdateSizeConstraintSet")
    def update_size_constraint_set(
        self,
        context: RequestContext,
        size_constraint_set_id: ResourceId,
        change_token: ChangeToken,
        updates: SizeConstraintSetUpdates,
    ) -> UpdateSizeConstraintSetResponse:
        raise NotImplementedError

    @handler("UpdateSqlInjectionMatchSet")
    def update_sql_injection_match_set(
        self,
        context: RequestContext,
        sql_injection_match_set_id: ResourceId,
        change_token: ChangeToken,
        updates: SqlInjectionMatchSetUpdates,
    ) -> UpdateSqlInjectionMatchSetResponse:
        raise NotImplementedError

    @handler("UpdateWebACL")
    def update_web_acl(
        self,
        context: RequestContext,
        web_acl_id: ResourceId,
        change_token: ChangeToken,
        updates: WebACLUpdates = None,
        default_action: WafAction = None,
    ) -> UpdateWebACLResponse:
        raise NotImplementedError

    @handler("UpdateXssMatchSet")
    def update_xss_match_set(
        self,
        context: RequestContext,
        xss_match_set_id: ResourceId,
        change_token: ChangeToken,
        updates: XssMatchSetUpdates,
    ) -> UpdateXssMatchSetResponse:
        raise NotImplementedError
