import sys
from datetime import datetime
from typing import Dict, List, Optional

if sys.version_info >= (3, 8):
    from typing import TypedDict
else:
    from typing_extensions import TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

Action = str
Boolean = bool
Country = str
CustomHTTPHeaderName = str
CustomHTTPHeaderValue = str
DownloadUrl = str
EntityDescription = str
EntityId = str
EntityName = str
ErrorMessage = str
ErrorReason = str
FieldIdentifier = str
FieldToMatchData = str
ForwardedIPHeaderName = str
HTTPMethod = str
HTTPVersion = str
HeaderName = str
HeaderValue = str
IPAddress = str
IPString = str
JsonPointerPath = str
LabelMatchKey = str
LabelName = str
LockToken = str
LoginPathString = str
MetricName = str
NextMarker = str
OutputUrl = str
PaginationLimit = int
ParameterExceptionParameter = str
PolicyString = str
RegexPatternString = str
ReleaseNotes = str
ResourceArn = str
ResponseCode = int
ResponseContent = str
ResponseStatusCode = int
RulePriority = int
TagKey = str
TagValue = str
TextTransformationPriority = int
TimeWindowDay = int
URIString = str
VendorName = str
VersionKeyString = str


class ActionValue(str):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    COUNT = "COUNT"
    CAPTCHA = "CAPTCHA"
    EXCLUDED_AS_COUNT = "EXCLUDED_AS_COUNT"


class BodyParsingFallbackBehavior(str):
    MATCH = "MATCH"
    NO_MATCH = "NO_MATCH"
    EVALUATE_AS_STRING = "EVALUATE_AS_STRING"


class ComparisonOperator(str):
    EQ = "EQ"
    NE = "NE"
    LE = "LE"
    LT = "LT"
    GE = "GE"
    GT = "GT"


class CountryCode(str):
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


class FailureReason(str):
    TOKEN_MISSING = "TOKEN_MISSING"
    TOKEN_EXPIRED = "TOKEN_EXPIRED"


class FallbackBehavior(str):
    MATCH = "MATCH"
    NO_MATCH = "NO_MATCH"


class FilterBehavior(str):
    KEEP = "KEEP"
    DROP = "DROP"


class FilterRequirement(str):
    MEETS_ALL = "MEETS_ALL"
    MEETS_ANY = "MEETS_ANY"


class ForwardedIPPosition(str):
    FIRST = "FIRST"
    LAST = "LAST"
    ANY = "ANY"


class IPAddressVersion(str):
    IPV4 = "IPV4"
    IPV6 = "IPV6"


class JsonMatchScope(str):
    ALL = "ALL"
    KEY = "KEY"
    VALUE = "VALUE"


class LabelMatchScope(str):
    LABEL = "LABEL"
    NAMESPACE = "NAMESPACE"


class ParameterExceptionField(str):
    WEB_ACL = "WEB_ACL"
    RULE_GROUP = "RULE_GROUP"
    REGEX_PATTERN_SET = "REGEX_PATTERN_SET"
    IP_SET = "IP_SET"
    MANAGED_RULE_SET = "MANAGED_RULE_SET"
    RULE = "RULE"
    EXCLUDED_RULE = "EXCLUDED_RULE"
    STATEMENT = "STATEMENT"
    BYTE_MATCH_STATEMENT = "BYTE_MATCH_STATEMENT"
    SQLI_MATCH_STATEMENT = "SQLI_MATCH_STATEMENT"
    XSS_MATCH_STATEMENT = "XSS_MATCH_STATEMENT"
    SIZE_CONSTRAINT_STATEMENT = "SIZE_CONSTRAINT_STATEMENT"
    GEO_MATCH_STATEMENT = "GEO_MATCH_STATEMENT"
    RATE_BASED_STATEMENT = "RATE_BASED_STATEMENT"
    RULE_GROUP_REFERENCE_STATEMENT = "RULE_GROUP_REFERENCE_STATEMENT"
    REGEX_PATTERN_REFERENCE_STATEMENT = "REGEX_PATTERN_REFERENCE_STATEMENT"
    IP_SET_REFERENCE_STATEMENT = "IP_SET_REFERENCE_STATEMENT"
    MANAGED_RULE_SET_STATEMENT = "MANAGED_RULE_SET_STATEMENT"
    LABEL_MATCH_STATEMENT = "LABEL_MATCH_STATEMENT"
    AND_STATEMENT = "AND_STATEMENT"
    OR_STATEMENT = "OR_STATEMENT"
    NOT_STATEMENT = "NOT_STATEMENT"
    IP_ADDRESS = "IP_ADDRESS"
    IP_ADDRESS_VERSION = "IP_ADDRESS_VERSION"
    FIELD_TO_MATCH = "FIELD_TO_MATCH"
    TEXT_TRANSFORMATION = "TEXT_TRANSFORMATION"
    SINGLE_QUERY_ARGUMENT = "SINGLE_QUERY_ARGUMENT"
    SINGLE_HEADER = "SINGLE_HEADER"
    DEFAULT_ACTION = "DEFAULT_ACTION"
    RULE_ACTION = "RULE_ACTION"
    ENTITY_LIMIT = "ENTITY_LIMIT"
    OVERRIDE_ACTION = "OVERRIDE_ACTION"
    SCOPE_VALUE = "SCOPE_VALUE"
    RESOURCE_ARN = "RESOURCE_ARN"
    RESOURCE_TYPE = "RESOURCE_TYPE"
    TAGS = "TAGS"
    TAG_KEYS = "TAG_KEYS"
    METRIC_NAME = "METRIC_NAME"
    FIREWALL_MANAGER_STATEMENT = "FIREWALL_MANAGER_STATEMENT"
    FALLBACK_BEHAVIOR = "FALLBACK_BEHAVIOR"
    POSITION = "POSITION"
    FORWARDED_IP_CONFIG = "FORWARDED_IP_CONFIG"
    IP_SET_FORWARDED_IP_CONFIG = "IP_SET_FORWARDED_IP_CONFIG"
    HEADER_NAME = "HEADER_NAME"
    CUSTOM_REQUEST_HANDLING = "CUSTOM_REQUEST_HANDLING"
    RESPONSE_CONTENT_TYPE = "RESPONSE_CONTENT_TYPE"
    CUSTOM_RESPONSE = "CUSTOM_RESPONSE"
    CUSTOM_RESPONSE_BODY = "CUSTOM_RESPONSE_BODY"
    JSON_MATCH_PATTERN = "JSON_MATCH_PATTERN"
    JSON_MATCH_SCOPE = "JSON_MATCH_SCOPE"
    BODY_PARSING_FALLBACK_BEHAVIOR = "BODY_PARSING_FALLBACK_BEHAVIOR"
    LOGGING_FILTER = "LOGGING_FILTER"
    FILTER_CONDITION = "FILTER_CONDITION"
    EXPIRE_TIMESTAMP = "EXPIRE_TIMESTAMP"
    CHANGE_PROPAGATION_STATUS = "CHANGE_PROPAGATION_STATUS"
    ASSOCIABLE_RESOURCE = "ASSOCIABLE_RESOURCE"
    LOG_DESTINATION = "LOG_DESTINATION"
    MANAGED_RULE_GROUP_CONFIG = "MANAGED_RULE_GROUP_CONFIG"
    PAYLOAD_TYPE = "PAYLOAD_TYPE"


class PayloadType(str):
    JSON = "JSON"
    FORM_ENCODED = "FORM_ENCODED"


class Platform(str):
    IOS = "IOS"
    ANDROID = "ANDROID"


class PositionalConstraint(str):
    EXACTLY = "EXACTLY"
    STARTS_WITH = "STARTS_WITH"
    ENDS_WITH = "ENDS_WITH"
    CONTAINS = "CONTAINS"
    CONTAINS_WORD = "CONTAINS_WORD"


class RateBasedStatementAggregateKeyType(str):
    IP = "IP"
    FORWARDED_IP = "FORWARDED_IP"


class ResourceType(str):
    APPLICATION_LOAD_BALANCER = "APPLICATION_LOAD_BALANCER"
    API_GATEWAY = "API_GATEWAY"
    APPSYNC = "APPSYNC"


class ResponseContentType(str):
    TEXT_PLAIN = "TEXT_PLAIN"
    TEXT_HTML = "TEXT_HTML"
    APPLICATION_JSON = "APPLICATION_JSON"


class Scope(str):
    CLOUDFRONT = "CLOUDFRONT"
    REGIONAL = "REGIONAL"


class TextTransformationType(str):
    NONE = "NONE"
    COMPRESS_WHITE_SPACE = "COMPRESS_WHITE_SPACE"
    HTML_ENTITY_DECODE = "HTML_ENTITY_DECODE"
    LOWERCASE = "LOWERCASE"
    CMD_LINE = "CMD_LINE"
    URL_DECODE = "URL_DECODE"
    BASE64_DECODE = "BASE64_DECODE"
    HEX_DECODE = "HEX_DECODE"
    MD5 = "MD5"
    REPLACE_COMMENTS = "REPLACE_COMMENTS"
    ESCAPE_SEQ_DECODE = "ESCAPE_SEQ_DECODE"
    SQL_HEX_DECODE = "SQL_HEX_DECODE"
    CSS_DECODE = "CSS_DECODE"
    JS_DECODE = "JS_DECODE"
    NORMALIZE_PATH = "NORMALIZE_PATH"
    NORMALIZE_PATH_WIN = "NORMALIZE_PATH_WIN"
    REMOVE_NULLS = "REMOVE_NULLS"
    REPLACE_NULLS = "REPLACE_NULLS"
    BASE64_DECODE_EXT = "BASE64_DECODE_EXT"
    URL_DECODE_UNI = "URL_DECODE_UNI"
    UTF8_TO_UNICODE = "UTF8_TO_UNICODE"


class WAFAssociatedItemException(ServiceException):
    Message: Optional[ErrorMessage]


class WAFDuplicateItemException(ServiceException):
    Message: Optional[ErrorMessage]


class WAFExpiredManagedRuleGroupVersionException(ServiceException):
    Message: Optional[ErrorMessage]


class WAFInternalErrorException(ServiceException):
    Message: Optional[ErrorMessage]


class WAFInvalidOperationException(ServiceException):
    Message: Optional[ErrorMessage]


class WAFInvalidParameterException(ServiceException):
    message: Optional[ErrorMessage]
    Field: Optional[ParameterExceptionField]
    Parameter: Optional[ParameterExceptionParameter]
    Reason: Optional[ErrorReason]


class WAFInvalidPermissionPolicyException(ServiceException):
    Message: Optional[ErrorMessage]


class WAFInvalidResourceException(ServiceException):
    Message: Optional[ErrorMessage]


class WAFLimitsExceededException(ServiceException):
    Message: Optional[ErrorMessage]


class WAFLogDestinationPermissionIssueException(ServiceException):
    Message: Optional[ErrorMessage]


class WAFNonexistentItemException(ServiceException):
    Message: Optional[ErrorMessage]


class WAFOptimisticLockException(ServiceException):
    Message: Optional[ErrorMessage]


class WAFServiceLinkedRoleErrorException(ServiceException):
    message: Optional[ErrorMessage]


class WAFSubscriptionNotFoundException(ServiceException):
    Message: Optional[ErrorMessage]


class WAFTagOperationException(ServiceException):
    Message: Optional[ErrorMessage]


class WAFTagOperationInternalErrorException(ServiceException):
    Message: Optional[ErrorMessage]


class WAFUnavailableEntityException(ServiceException):
    Message: Optional[ErrorMessage]


class ActionCondition(TypedDict, total=False):
    Action: ActionValue


class All(TypedDict, total=False):
    pass


class AllQueryArguments(TypedDict, total=False):
    pass


class CustomHTTPHeader(TypedDict, total=False):
    Name: CustomHTTPHeaderName
    Value: CustomHTTPHeaderValue


CustomHTTPHeaders = List[CustomHTTPHeader]


class CustomRequestHandling(TypedDict, total=False):
    InsertHeaders: CustomHTTPHeaders


class AllowAction(TypedDict, total=False):
    CustomRequestHandling: Optional[CustomRequestHandling]


class TextTransformation(TypedDict, total=False):
    Priority: TextTransformationPriority
    Type: TextTransformationType


TextTransformations = List[TextTransformation]
JsonPointerPaths = List[JsonPointerPath]


class JsonMatchPattern(TypedDict, total=False):
    All: Optional[All]
    IncludedPaths: Optional[JsonPointerPaths]


class JsonBody(TypedDict, total=False):
    MatchPattern: JsonMatchPattern
    MatchScope: JsonMatchScope
    InvalidFallbackBehavior: Optional[BodyParsingFallbackBehavior]


class Method(TypedDict, total=False):
    pass


class Body(TypedDict, total=False):
    pass


class QueryString(TypedDict, total=False):
    pass


class UriPath(TypedDict, total=False):
    pass


class SingleQueryArgument(TypedDict, total=False):
    Name: FieldToMatchData


class SingleHeader(TypedDict, total=False):
    Name: FieldToMatchData


class FieldToMatch(TypedDict, total=False):
    SingleHeader: Optional[SingleHeader]
    SingleQueryArgument: Optional[SingleQueryArgument]
    AllQueryArguments: Optional[AllQueryArguments]
    UriPath: Optional[UriPath]
    QueryString: Optional[QueryString]
    Body: Optional[Body]
    Method: Optional[Method]
    JsonBody: Optional[JsonBody]


class RegexMatchStatement(TypedDict, total=False):
    RegexString: RegexPatternString
    FieldToMatch: FieldToMatch
    TextTransformations: TextTransformations


class LabelMatchStatement(TypedDict, total=False):
    Scope: LabelMatchScope
    Key: LabelMatchKey


class PasswordField(TypedDict, total=False):
    Identifier: FieldIdentifier


class UsernameField(TypedDict, total=False):
    Identifier: FieldIdentifier


class ManagedRuleGroupConfig(TypedDict, total=False):
    LoginPath: Optional[LoginPathString]
    PayloadType: Optional[PayloadType]
    UsernameField: Optional[UsernameField]
    PasswordField: Optional[PasswordField]


ManagedRuleGroupConfigs = List[ManagedRuleGroupConfig]


class Statement(TypedDict, total=False):
    ByteMatchStatement: Optional["ByteMatchStatement"]
    SqliMatchStatement: Optional["SqliMatchStatement"]
    XssMatchStatement: Optional["XssMatchStatement"]
    SizeConstraintStatement: Optional["SizeConstraintStatement"]
    GeoMatchStatement: Optional["GeoMatchStatement"]
    RuleGroupReferenceStatement: Optional["RuleGroupReferenceStatement"]
    IPSetReferenceStatement: Optional["IPSetReferenceStatement"]
    RegexPatternSetReferenceStatement: Optional["RegexPatternSetReferenceStatement"]
    RateBasedStatement: Optional["RateBasedStatement"]
    AndStatement: Optional["AndStatement"]
    OrStatement: Optional["OrStatement"]
    NotStatement: Optional["NotStatement"]
    ManagedRuleGroupStatement: Optional["ManagedRuleGroupStatement"]
    LabelMatchStatement: Optional["LabelMatchStatement"]
    RegexMatchStatement: Optional["RegexMatchStatement"]


class ExcludedRule(TypedDict, total=False):
    Name: EntityName


ExcludedRules = List[ExcludedRule]


class ManagedRuleGroupStatement(TypedDict, total=False):
    VendorName: VendorName
    Name: EntityName
    Version: Optional[VersionKeyString]
    ExcludedRules: Optional[ExcludedRules]
    ScopeDownStatement: Optional[Statement]
    ManagedRuleGroupConfigs: Optional[ManagedRuleGroupConfigs]


class NotStatement(TypedDict, total=False):
    Statement: Statement


Statements = List[Statement]


class OrStatement(TypedDict, total=False):
    Statements: Statements


class AndStatement(TypedDict, total=False):
    Statements: Statements


class ForwardedIPConfig(TypedDict, total=False):
    HeaderName: ForwardedIPHeaderName
    FallbackBehavior: FallbackBehavior


RateLimit = int


class RateBasedStatement(TypedDict, total=False):
    Limit: RateLimit
    AggregateKeyType: RateBasedStatementAggregateKeyType
    ScopeDownStatement: Optional[Statement]
    ForwardedIPConfig: Optional[ForwardedIPConfig]


class RegexPatternSetReferenceStatement(TypedDict, total=False):
    ARN: ResourceArn
    FieldToMatch: FieldToMatch
    TextTransformations: TextTransformations


class IPSetForwardedIPConfig(TypedDict, total=False):
    HeaderName: ForwardedIPHeaderName
    FallbackBehavior: FallbackBehavior
    Position: ForwardedIPPosition


class IPSetReferenceStatement(TypedDict, total=False):
    ARN: ResourceArn
    IPSetForwardedIPConfig: Optional[IPSetForwardedIPConfig]


class RuleGroupReferenceStatement(TypedDict, total=False):
    ARN: ResourceArn
    ExcludedRules: Optional[ExcludedRules]


CountryCodes = List[CountryCode]


class GeoMatchStatement(TypedDict, total=False):
    CountryCodes: Optional[CountryCodes]
    ForwardedIPConfig: Optional[ForwardedIPConfig]


Size = int


class SizeConstraintStatement(TypedDict, total=False):
    FieldToMatch: FieldToMatch
    ComparisonOperator: ComparisonOperator
    Size: Size
    TextTransformations: TextTransformations


class XssMatchStatement(TypedDict, total=False):
    FieldToMatch: FieldToMatch
    TextTransformations: TextTransformations


class SqliMatchStatement(TypedDict, total=False):
    FieldToMatch: FieldToMatch
    TextTransformations: TextTransformations


SearchString = bytes


class ByteMatchStatement(TypedDict, total=False):
    SearchString: SearchString
    FieldToMatch: FieldToMatch
    TextTransformations: TextTransformations
    PositionalConstraint: PositionalConstraint


class AssociateWebACLRequest(ServiceRequest):
    WebACLArn: ResourceArn
    ResourceArn: ResourceArn


class AssociateWebACLResponse(TypedDict, total=False):
    pass


class CustomResponse(TypedDict, total=False):
    ResponseCode: ResponseStatusCode
    CustomResponseBodyKey: Optional[EntityName]
    ResponseHeaders: Optional[CustomHTTPHeaders]


class BlockAction(TypedDict, total=False):
    CustomResponse: Optional[CustomResponse]


CapacityUnit = int


class CaptchaAction(TypedDict, total=False):
    CustomRequestHandling: Optional[CustomRequestHandling]


TimeWindowSecond = int


class ImmunityTimeProperty(TypedDict, total=False):
    ImmunityTime: TimeWindowSecond


class CaptchaConfig(TypedDict, total=False):
    ImmunityTimeProperty: Optional[ImmunityTimeProperty]


SolveTimestamp = int


class CaptchaResponse(TypedDict, total=False):
    ResponseCode: Optional[ResponseCode]
    SolveTimestamp: Optional[SolveTimestamp]
    FailureReason: Optional[FailureReason]


class VisibilityConfig(TypedDict, total=False):
    SampledRequestsEnabled: Boolean
    CloudWatchMetricsEnabled: Boolean
    MetricName: MetricName


class Label(TypedDict, total=False):
    Name: LabelName


Labels = List[Label]


class NoneAction(TypedDict, total=False):
    pass


class CountAction(TypedDict, total=False):
    CustomRequestHandling: Optional[CustomRequestHandling]


OverrideAction = TypedDict(
    "OverrideAction",
    {
        "Count": Optional[CountAction],
        "None": Optional[NoneAction],
    },
    total=False,
)


class RuleAction(TypedDict, total=False):
    Block: Optional[BlockAction]
    Allow: Optional[AllowAction]
    Count: Optional[CountAction]
    Captcha: Optional[CaptchaAction]


class Rule(TypedDict, total=False):
    Name: EntityName
    Priority: RulePriority
    Statement: Statement
    Action: Optional[RuleAction]
    OverrideAction: Optional[OverrideAction]
    RuleLabels: Optional[Labels]
    VisibilityConfig: VisibilityConfig
    CaptchaConfig: Optional[CaptchaConfig]


Rules = List[Rule]


class CheckCapacityRequest(ServiceRequest):
    Scope: Scope
    Rules: Rules


ConsumedCapacity = int


class CheckCapacityResponse(TypedDict, total=False):
    Capacity: Optional[ConsumedCapacity]


class LabelNameCondition(TypedDict, total=False):
    LabelName: LabelName


class Condition(TypedDict, total=False):
    ActionCondition: Optional[ActionCondition]
    LabelNameCondition: Optional[LabelNameCondition]


Conditions = List[Condition]


class Tag(TypedDict, total=False):
    Key: TagKey
    Value: TagValue


TagList = List[Tag]
IPAddresses = List[IPAddress]


class CreateIPSetRequest(ServiceRequest):
    Name: EntityName
    Scope: Scope
    Description: Optional[EntityDescription]
    IPAddressVersion: IPAddressVersion
    Addresses: IPAddresses
    Tags: Optional[TagList]


class IPSetSummary(TypedDict, total=False):
    Name: Optional[EntityName]
    Id: Optional[EntityId]
    Description: Optional[EntityDescription]
    LockToken: Optional[LockToken]
    ARN: Optional[ResourceArn]


class CreateIPSetResponse(TypedDict, total=False):
    Summary: Optional[IPSetSummary]


class Regex(TypedDict, total=False):
    RegexString: Optional[RegexPatternString]


RegularExpressionList = List[Regex]


class CreateRegexPatternSetRequest(ServiceRequest):
    Name: EntityName
    Scope: Scope
    Description: Optional[EntityDescription]
    RegularExpressionList: RegularExpressionList
    Tags: Optional[TagList]


class RegexPatternSetSummary(TypedDict, total=False):
    Name: Optional[EntityName]
    Id: Optional[EntityId]
    Description: Optional[EntityDescription]
    LockToken: Optional[LockToken]
    ARN: Optional[ResourceArn]


class CreateRegexPatternSetResponse(TypedDict, total=False):
    Summary: Optional[RegexPatternSetSummary]


class CustomResponseBody(TypedDict, total=False):
    ContentType: ResponseContentType
    Content: ResponseContent


CustomResponseBodies = Dict[EntityName, CustomResponseBody]


class CreateRuleGroupRequest(ServiceRequest):
    Name: EntityName
    Scope: Scope
    Capacity: CapacityUnit
    Description: Optional[EntityDescription]
    Rules: Optional[Rules]
    VisibilityConfig: VisibilityConfig
    Tags: Optional[TagList]
    CustomResponseBodies: Optional[CustomResponseBodies]


class RuleGroupSummary(TypedDict, total=False):
    Name: Optional[EntityName]
    Id: Optional[EntityId]
    Description: Optional[EntityDescription]
    LockToken: Optional[LockToken]
    ARN: Optional[ResourceArn]


class CreateRuleGroupResponse(TypedDict, total=False):
    Summary: Optional[RuleGroupSummary]


class DefaultAction(TypedDict, total=False):
    Block: Optional[BlockAction]
    Allow: Optional[AllowAction]


class CreateWebACLRequest(ServiceRequest):
    Name: EntityName
    Scope: Scope
    DefaultAction: DefaultAction
    Description: Optional[EntityDescription]
    Rules: Optional[Rules]
    VisibilityConfig: VisibilityConfig
    Tags: Optional[TagList]
    CustomResponseBodies: Optional[CustomResponseBodies]
    CaptchaConfig: Optional[CaptchaConfig]


class WebACLSummary(TypedDict, total=False):
    Name: Optional[EntityName]
    Id: Optional[EntityId]
    Description: Optional[EntityDescription]
    LockToken: Optional[LockToken]
    ARN: Optional[ResourceArn]


class CreateWebACLResponse(TypedDict, total=False):
    Summary: Optional[WebACLSummary]


class DeleteFirewallManagerRuleGroupsRequest(ServiceRequest):
    WebACLArn: ResourceArn
    WebACLLockToken: LockToken


class DeleteFirewallManagerRuleGroupsResponse(TypedDict, total=False):
    NextWebACLLockToken: Optional[LockToken]


class DeleteIPSetRequest(ServiceRequest):
    Name: EntityName
    Scope: Scope
    Id: EntityId
    LockToken: LockToken


class DeleteIPSetResponse(TypedDict, total=False):
    pass


class DeleteLoggingConfigurationRequest(ServiceRequest):
    ResourceArn: ResourceArn


class DeleteLoggingConfigurationResponse(TypedDict, total=False):
    pass


class DeletePermissionPolicyRequest(ServiceRequest):
    ResourceArn: ResourceArn


class DeletePermissionPolicyResponse(TypedDict, total=False):
    pass


class DeleteRegexPatternSetRequest(ServiceRequest):
    Name: EntityName
    Scope: Scope
    Id: EntityId
    LockToken: LockToken


class DeleteRegexPatternSetResponse(TypedDict, total=False):
    pass


class DeleteRuleGroupRequest(ServiceRequest):
    Name: EntityName
    Scope: Scope
    Id: EntityId
    LockToken: LockToken


class DeleteRuleGroupResponse(TypedDict, total=False):
    pass


class DeleteWebACLRequest(ServiceRequest):
    Name: EntityName
    Scope: Scope
    Id: EntityId
    LockToken: LockToken


class DeleteWebACLResponse(TypedDict, total=False):
    pass


class DescribeManagedRuleGroupRequest(ServiceRequest):
    VendorName: VendorName
    Name: EntityName
    Scope: Scope
    VersionName: Optional[VersionKeyString]


class LabelSummary(TypedDict, total=False):
    Name: Optional[LabelName]


LabelSummaries = List[LabelSummary]


class RuleSummary(TypedDict, total=False):
    Name: Optional[EntityName]
    Action: Optional[RuleAction]


RuleSummaries = List[RuleSummary]


class DescribeManagedRuleGroupResponse(TypedDict, total=False):
    VersionName: Optional[VersionKeyString]
    SnsTopicArn: Optional[ResourceArn]
    Capacity: Optional[CapacityUnit]
    Rules: Optional[RuleSummaries]
    LabelNamespace: Optional[LabelName]
    AvailableLabels: Optional[LabelSummaries]
    ConsumedLabels: Optional[LabelSummaries]


class DisassociateWebACLRequest(ServiceRequest):
    ResourceArn: ResourceArn


class DisassociateWebACLResponse(TypedDict, total=False):
    pass


class Filter(TypedDict, total=False):
    Behavior: FilterBehavior
    Requirement: FilterRequirement
    Conditions: Conditions


Filters = List[Filter]


class FirewallManagerStatement(TypedDict, total=False):
    ManagedRuleGroupStatement: Optional[ManagedRuleGroupStatement]
    RuleGroupReferenceStatement: Optional[RuleGroupReferenceStatement]


class FirewallManagerRuleGroup(TypedDict, total=False):
    Name: EntityName
    Priority: RulePriority
    FirewallManagerStatement: FirewallManagerStatement
    OverrideAction: OverrideAction
    VisibilityConfig: VisibilityConfig


FirewallManagerRuleGroups = List[FirewallManagerRuleGroup]


class GenerateMobileSdkReleaseUrlRequest(ServiceRequest):
    Platform: Platform
    ReleaseVersion: VersionKeyString


class GenerateMobileSdkReleaseUrlResponse(TypedDict, total=False):
    Url: Optional[DownloadUrl]


class GetIPSetRequest(ServiceRequest):
    Name: EntityName
    Scope: Scope
    Id: EntityId


class IPSet(TypedDict, total=False):
    Name: EntityName
    Id: EntityId
    ARN: ResourceArn
    Description: Optional[EntityDescription]
    IPAddressVersion: IPAddressVersion
    Addresses: IPAddresses


class GetIPSetResponse(TypedDict, total=False):
    IPSet: Optional[IPSet]
    LockToken: Optional[LockToken]


class GetLoggingConfigurationRequest(ServiceRequest):
    ResourceArn: ResourceArn


class LoggingFilter(TypedDict, total=False):
    Filters: Filters
    DefaultBehavior: FilterBehavior


RedactedFields = List[FieldToMatch]
LogDestinationConfigs = List[ResourceArn]


class LoggingConfiguration(TypedDict, total=False):
    ResourceArn: ResourceArn
    LogDestinationConfigs: LogDestinationConfigs
    RedactedFields: Optional[RedactedFields]
    ManagedByFirewallManager: Optional[Boolean]
    LoggingFilter: Optional[LoggingFilter]


class GetLoggingConfigurationResponse(TypedDict, total=False):
    LoggingConfiguration: Optional[LoggingConfiguration]


class GetManagedRuleSetRequest(ServiceRequest):
    Name: EntityName
    Scope: Scope
    Id: EntityId


Timestamp = datetime


class ManagedRuleSetVersion(TypedDict, total=False):
    AssociatedRuleGroupArn: Optional[ResourceArn]
    Capacity: Optional[CapacityUnit]
    ForecastedLifetime: Optional[TimeWindowDay]
    PublishTimestamp: Optional[Timestamp]
    LastUpdateTimestamp: Optional[Timestamp]
    ExpiryTimestamp: Optional[Timestamp]


PublishedVersions = Dict[VersionKeyString, ManagedRuleSetVersion]


class ManagedRuleSet(TypedDict, total=False):
    Name: EntityName
    Id: EntityId
    ARN: ResourceArn
    Description: Optional[EntityDescription]
    PublishedVersions: Optional[PublishedVersions]
    RecommendedVersion: Optional[VersionKeyString]
    LabelNamespace: Optional[LabelName]


class GetManagedRuleSetResponse(TypedDict, total=False):
    ManagedRuleSet: Optional[ManagedRuleSet]
    LockToken: Optional[LockToken]


class GetMobileSdkReleaseRequest(ServiceRequest):
    Platform: Platform
    ReleaseVersion: VersionKeyString


class MobileSdkRelease(TypedDict, total=False):
    ReleaseVersion: Optional[VersionKeyString]
    Timestamp: Optional[Timestamp]
    ReleaseNotes: Optional[ReleaseNotes]
    Tags: Optional[TagList]


class GetMobileSdkReleaseResponse(TypedDict, total=False):
    MobileSdkRelease: Optional[MobileSdkRelease]


class GetPermissionPolicyRequest(ServiceRequest):
    ResourceArn: ResourceArn


class GetPermissionPolicyResponse(TypedDict, total=False):
    Policy: Optional[PolicyString]


class GetRateBasedStatementManagedKeysRequest(ServiceRequest):
    Scope: Scope
    WebACLName: EntityName
    WebACLId: EntityId
    RuleGroupRuleName: Optional[EntityName]
    RuleName: EntityName


class RateBasedStatementManagedKeysIPSet(TypedDict, total=False):
    IPAddressVersion: Optional[IPAddressVersion]
    Addresses: Optional[IPAddresses]


class GetRateBasedStatementManagedKeysResponse(TypedDict, total=False):
    ManagedKeysIPV4: Optional[RateBasedStatementManagedKeysIPSet]
    ManagedKeysIPV6: Optional[RateBasedStatementManagedKeysIPSet]


class GetRegexPatternSetRequest(ServiceRequest):
    Name: EntityName
    Scope: Scope
    Id: EntityId


class RegexPatternSet(TypedDict, total=False):
    Name: Optional[EntityName]
    Id: Optional[EntityId]
    ARN: Optional[ResourceArn]
    Description: Optional[EntityDescription]
    RegularExpressionList: Optional[RegularExpressionList]


class GetRegexPatternSetResponse(TypedDict, total=False):
    RegexPatternSet: Optional[RegexPatternSet]
    LockToken: Optional[LockToken]


class GetRuleGroupRequest(ServiceRequest):
    Name: Optional[EntityName]
    Scope: Optional[Scope]
    Id: Optional[EntityId]
    ARN: Optional[ResourceArn]


class RuleGroup(TypedDict, total=False):
    Name: EntityName
    Id: EntityId
    Capacity: CapacityUnit
    ARN: ResourceArn
    Description: Optional[EntityDescription]
    Rules: Optional[Rules]
    VisibilityConfig: VisibilityConfig
    LabelNamespace: Optional[LabelName]
    CustomResponseBodies: Optional[CustomResponseBodies]
    AvailableLabels: Optional[LabelSummaries]
    ConsumedLabels: Optional[LabelSummaries]


class GetRuleGroupResponse(TypedDict, total=False):
    RuleGroup: Optional[RuleGroup]
    LockToken: Optional[LockToken]


ListMaxItems = int


class TimeWindow(TypedDict, total=False):
    StartTime: Timestamp
    EndTime: Timestamp


class GetSampledRequestsRequest(ServiceRequest):
    WebAclArn: ResourceArn
    RuleMetricName: MetricName
    Scope: Scope
    TimeWindow: TimeWindow
    MaxItems: ListMaxItems


PopulationSize = int


class HTTPHeader(TypedDict, total=False):
    Name: Optional[HeaderName]
    Value: Optional[HeaderValue]


HTTPHeaders = List[HTTPHeader]
SampleWeight = int


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
    RuleNameWithinRuleGroup: Optional[EntityName]
    RequestHeadersInserted: Optional[HTTPHeaders]
    ResponseCodeSent: Optional[ResponseStatusCode]
    Labels: Optional[Labels]
    CaptchaResponse: Optional[CaptchaResponse]


SampledHTTPRequests = List[SampledHTTPRequest]


class GetSampledRequestsResponse(TypedDict, total=False):
    SampledRequests: Optional[SampledHTTPRequests]
    PopulationSize: Optional[PopulationSize]
    TimeWindow: Optional[TimeWindow]


class GetWebACLForResourceRequest(ServiceRequest):
    ResourceArn: ResourceArn


class WebACL(TypedDict, total=False):
    Name: EntityName
    Id: EntityId
    ARN: ResourceArn
    DefaultAction: DefaultAction
    Description: Optional[EntityDescription]
    Rules: Optional[Rules]
    VisibilityConfig: VisibilityConfig
    Capacity: Optional[ConsumedCapacity]
    PreProcessFirewallManagerRuleGroups: Optional[FirewallManagerRuleGroups]
    PostProcessFirewallManagerRuleGroups: Optional[FirewallManagerRuleGroups]
    ManagedByFirewallManager: Optional[Boolean]
    LabelNamespace: Optional[LabelName]
    CustomResponseBodies: Optional[CustomResponseBodies]
    CaptchaConfig: Optional[CaptchaConfig]


class GetWebACLForResourceResponse(TypedDict, total=False):
    WebACL: Optional[WebACL]


class GetWebACLRequest(ServiceRequest):
    Name: EntityName
    Scope: Scope
    Id: EntityId


class GetWebACLResponse(TypedDict, total=False):
    WebACL: Optional[WebACL]
    LockToken: Optional[LockToken]
    ApplicationIntegrationURL: Optional[OutputUrl]


IPSetSummaries = List[IPSetSummary]


class ListAvailableManagedRuleGroupVersionsRequest(ServiceRequest):
    VendorName: VendorName
    Name: EntityName
    Scope: Scope
    NextMarker: Optional[NextMarker]
    Limit: Optional[PaginationLimit]


class ManagedRuleGroupVersion(TypedDict, total=False):
    Name: Optional[VersionKeyString]
    LastUpdateTimestamp: Optional[Timestamp]


ManagedRuleGroupVersions = List[ManagedRuleGroupVersion]


class ListAvailableManagedRuleGroupVersionsResponse(TypedDict, total=False):
    NextMarker: Optional[NextMarker]
    Versions: Optional[ManagedRuleGroupVersions]


class ListAvailableManagedRuleGroupsRequest(ServiceRequest):
    Scope: Scope
    NextMarker: Optional[NextMarker]
    Limit: Optional[PaginationLimit]


class ManagedRuleGroupSummary(TypedDict, total=False):
    VendorName: Optional[VendorName]
    Name: Optional[EntityName]
    Description: Optional[EntityDescription]


ManagedRuleGroupSummaries = List[ManagedRuleGroupSummary]


class ListAvailableManagedRuleGroupsResponse(TypedDict, total=False):
    NextMarker: Optional[NextMarker]
    ManagedRuleGroups: Optional[ManagedRuleGroupSummaries]


class ListIPSetsRequest(ServiceRequest):
    Scope: Scope
    NextMarker: Optional[NextMarker]
    Limit: Optional[PaginationLimit]


class ListIPSetsResponse(TypedDict, total=False):
    NextMarker: Optional[NextMarker]
    IPSets: Optional[IPSetSummaries]


class ListLoggingConfigurationsRequest(ServiceRequest):
    Scope: Scope
    NextMarker: Optional[NextMarker]
    Limit: Optional[PaginationLimit]


LoggingConfigurations = List[LoggingConfiguration]


class ListLoggingConfigurationsResponse(TypedDict, total=False):
    LoggingConfigurations: Optional[LoggingConfigurations]
    NextMarker: Optional[NextMarker]


class ListManagedRuleSetsRequest(ServiceRequest):
    Scope: Scope
    NextMarker: Optional[NextMarker]
    Limit: Optional[PaginationLimit]


class ManagedRuleSetSummary(TypedDict, total=False):
    Name: Optional[EntityName]
    Id: Optional[EntityId]
    Description: Optional[EntityDescription]
    LockToken: Optional[LockToken]
    ARN: Optional[ResourceArn]
    LabelNamespace: Optional[LabelName]


ManagedRuleSetSummaries = List[ManagedRuleSetSummary]


class ListManagedRuleSetsResponse(TypedDict, total=False):
    NextMarker: Optional[NextMarker]
    ManagedRuleSets: Optional[ManagedRuleSetSummaries]


class ListMobileSdkReleasesRequest(ServiceRequest):
    Platform: Platform
    NextMarker: Optional[NextMarker]
    Limit: Optional[PaginationLimit]


class ReleaseSummary(TypedDict, total=False):
    ReleaseVersion: Optional[VersionKeyString]
    Timestamp: Optional[Timestamp]


ReleaseSummaries = List[ReleaseSummary]


class ListMobileSdkReleasesResponse(TypedDict, total=False):
    ReleaseSummaries: Optional[ReleaseSummaries]
    NextMarker: Optional[NextMarker]


class ListRegexPatternSetsRequest(ServiceRequest):
    Scope: Scope
    NextMarker: Optional[NextMarker]
    Limit: Optional[PaginationLimit]


RegexPatternSetSummaries = List[RegexPatternSetSummary]


class ListRegexPatternSetsResponse(TypedDict, total=False):
    NextMarker: Optional[NextMarker]
    RegexPatternSets: Optional[RegexPatternSetSummaries]


class ListResourcesForWebACLRequest(ServiceRequest):
    WebACLArn: ResourceArn
    ResourceType: Optional[ResourceType]


ResourceArns = List[ResourceArn]


class ListResourcesForWebACLResponse(TypedDict, total=False):
    ResourceArns: Optional[ResourceArns]


class ListRuleGroupsRequest(ServiceRequest):
    Scope: Scope
    NextMarker: Optional[NextMarker]
    Limit: Optional[PaginationLimit]


RuleGroupSummaries = List[RuleGroupSummary]


class ListRuleGroupsResponse(TypedDict, total=False):
    NextMarker: Optional[NextMarker]
    RuleGroups: Optional[RuleGroupSummaries]


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
    Scope: Scope
    NextMarker: Optional[NextMarker]
    Limit: Optional[PaginationLimit]


WebACLSummaries = List[WebACLSummary]


class ListWebACLsResponse(TypedDict, total=False):
    NextMarker: Optional[NextMarker]
    WebACLs: Optional[WebACLSummaries]


class PutLoggingConfigurationRequest(ServiceRequest):
    LoggingConfiguration: LoggingConfiguration


class PutLoggingConfigurationResponse(TypedDict, total=False):
    LoggingConfiguration: Optional[LoggingConfiguration]


class VersionToPublish(TypedDict, total=False):
    AssociatedRuleGroupArn: Optional[ResourceArn]
    ForecastedLifetime: Optional[TimeWindowDay]


VersionsToPublish = Dict[VersionKeyString, VersionToPublish]


class PutManagedRuleSetVersionsRequest(ServiceRequest):
    Name: EntityName
    Scope: Scope
    Id: EntityId
    LockToken: LockToken
    RecommendedVersion: Optional[VersionKeyString]
    VersionsToPublish: Optional[VersionsToPublish]


class PutManagedRuleSetVersionsResponse(TypedDict, total=False):
    NextLockToken: Optional[LockToken]


class PutPermissionPolicyRequest(ServiceRequest):
    ResourceArn: ResourceArn
    Policy: PolicyString


class PutPermissionPolicyResponse(TypedDict, total=False):
    pass


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


class UpdateIPSetRequest(ServiceRequest):
    Name: EntityName
    Scope: Scope
    Id: EntityId
    Description: Optional[EntityDescription]
    Addresses: IPAddresses
    LockToken: LockToken


class UpdateIPSetResponse(TypedDict, total=False):
    NextLockToken: Optional[LockToken]


class UpdateManagedRuleSetVersionExpiryDateRequest(ServiceRequest):
    Name: EntityName
    Scope: Scope
    Id: EntityId
    LockToken: LockToken
    VersionToExpire: VersionKeyString
    ExpiryTimestamp: Timestamp


class UpdateManagedRuleSetVersionExpiryDateResponse(TypedDict, total=False):
    ExpiringVersion: Optional[VersionKeyString]
    ExpiryTimestamp: Optional[Timestamp]
    NextLockToken: Optional[LockToken]


class UpdateRegexPatternSetRequest(ServiceRequest):
    Name: EntityName
    Scope: Scope
    Id: EntityId
    Description: Optional[EntityDescription]
    RegularExpressionList: RegularExpressionList
    LockToken: LockToken


class UpdateRegexPatternSetResponse(TypedDict, total=False):
    NextLockToken: Optional[LockToken]


class UpdateRuleGroupRequest(ServiceRequest):
    Name: EntityName
    Scope: Scope
    Id: EntityId
    Description: Optional[EntityDescription]
    Rules: Optional[Rules]
    VisibilityConfig: VisibilityConfig
    LockToken: LockToken
    CustomResponseBodies: Optional[CustomResponseBodies]


class UpdateRuleGroupResponse(TypedDict, total=False):
    NextLockToken: Optional[LockToken]


class UpdateWebACLRequest(ServiceRequest):
    Name: EntityName
    Scope: Scope
    Id: EntityId
    DefaultAction: DefaultAction
    Description: Optional[EntityDescription]
    Rules: Optional[Rules]
    VisibilityConfig: VisibilityConfig
    LockToken: LockToken
    CustomResponseBodies: Optional[CustomResponseBodies]
    CaptchaConfig: Optional[CaptchaConfig]


class UpdateWebACLResponse(TypedDict, total=False):
    NextLockToken: Optional[LockToken]


class Wafv2Api:

    service = "wafv2"
    version = "2019-07-29"

    @handler("AssociateWebACL")
    def associate_web_acl(
        self, context: RequestContext, web_acl_arn: ResourceArn, resource_arn: ResourceArn
    ) -> AssociateWebACLResponse:
        raise NotImplementedError

    @handler("CheckCapacity")
    def check_capacity(
        self, context: RequestContext, scope: Scope, rules: Rules
    ) -> CheckCapacityResponse:
        raise NotImplementedError

    @handler("CreateIPSet")
    def create_ip_set(
        self,
        context: RequestContext,
        name: EntityName,
        scope: Scope,
        ip_address_version: IPAddressVersion,
        addresses: IPAddresses,
        description: EntityDescription = None,
        tags: TagList = None,
    ) -> CreateIPSetResponse:
        raise NotImplementedError

    @handler("CreateRegexPatternSet")
    def create_regex_pattern_set(
        self,
        context: RequestContext,
        name: EntityName,
        scope: Scope,
        regular_expression_list: RegularExpressionList,
        description: EntityDescription = None,
        tags: TagList = None,
    ) -> CreateRegexPatternSetResponse:
        raise NotImplementedError

    @handler("CreateRuleGroup")
    def create_rule_group(
        self,
        context: RequestContext,
        name: EntityName,
        scope: Scope,
        capacity: CapacityUnit,
        visibility_config: VisibilityConfig,
        description: EntityDescription = None,
        rules: Rules = None,
        tags: TagList = None,
        custom_response_bodies: CustomResponseBodies = None,
    ) -> CreateRuleGroupResponse:
        raise NotImplementedError

    @handler("CreateWebACL")
    def create_web_acl(
        self,
        context: RequestContext,
        name: EntityName,
        scope: Scope,
        default_action: DefaultAction,
        visibility_config: VisibilityConfig,
        description: EntityDescription = None,
        rules: Rules = None,
        tags: TagList = None,
        custom_response_bodies: CustomResponseBodies = None,
        captcha_config: CaptchaConfig = None,
    ) -> CreateWebACLResponse:
        raise NotImplementedError

    @handler("DeleteFirewallManagerRuleGroups")
    def delete_firewall_manager_rule_groups(
        self, context: RequestContext, web_acl_arn: ResourceArn, web_acl_lock_token: LockToken
    ) -> DeleteFirewallManagerRuleGroupsResponse:
        raise NotImplementedError

    @handler("DeleteIPSet")
    def delete_ip_set(
        self,
        context: RequestContext,
        name: EntityName,
        scope: Scope,
        id: EntityId,
        lock_token: LockToken,
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

    @handler("DeleteRegexPatternSet")
    def delete_regex_pattern_set(
        self,
        context: RequestContext,
        name: EntityName,
        scope: Scope,
        id: EntityId,
        lock_token: LockToken,
    ) -> DeleteRegexPatternSetResponse:
        raise NotImplementedError

    @handler("DeleteRuleGroup")
    def delete_rule_group(
        self,
        context: RequestContext,
        name: EntityName,
        scope: Scope,
        id: EntityId,
        lock_token: LockToken,
    ) -> DeleteRuleGroupResponse:
        raise NotImplementedError

    @handler("DeleteWebACL")
    def delete_web_acl(
        self,
        context: RequestContext,
        name: EntityName,
        scope: Scope,
        id: EntityId,
        lock_token: LockToken,
    ) -> DeleteWebACLResponse:
        raise NotImplementedError

    @handler("DescribeManagedRuleGroup")
    def describe_managed_rule_group(
        self,
        context: RequestContext,
        vendor_name: VendorName,
        name: EntityName,
        scope: Scope,
        version_name: VersionKeyString = None,
    ) -> DescribeManagedRuleGroupResponse:
        raise NotImplementedError

    @handler("DisassociateWebACL")
    def disassociate_web_acl(
        self, context: RequestContext, resource_arn: ResourceArn
    ) -> DisassociateWebACLResponse:
        raise NotImplementedError

    @handler("GenerateMobileSdkReleaseUrl")
    def generate_mobile_sdk_release_url(
        self, context: RequestContext, platform: Platform, release_version: VersionKeyString
    ) -> GenerateMobileSdkReleaseUrlResponse:
        raise NotImplementedError

    @handler("GetIPSet")
    def get_ip_set(
        self, context: RequestContext, name: EntityName, scope: Scope, id: EntityId
    ) -> GetIPSetResponse:
        raise NotImplementedError

    @handler("GetLoggingConfiguration")
    def get_logging_configuration(
        self, context: RequestContext, resource_arn: ResourceArn
    ) -> GetLoggingConfigurationResponse:
        raise NotImplementedError

    @handler("GetManagedRuleSet")
    def get_managed_rule_set(
        self, context: RequestContext, name: EntityName, scope: Scope, id: EntityId
    ) -> GetManagedRuleSetResponse:
        raise NotImplementedError

    @handler("GetMobileSdkRelease")
    def get_mobile_sdk_release(
        self, context: RequestContext, platform: Platform, release_version: VersionKeyString
    ) -> GetMobileSdkReleaseResponse:
        raise NotImplementedError

    @handler("GetPermissionPolicy")
    def get_permission_policy(
        self, context: RequestContext, resource_arn: ResourceArn
    ) -> GetPermissionPolicyResponse:
        raise NotImplementedError

    @handler("GetRateBasedStatementManagedKeys")
    def get_rate_based_statement_managed_keys(
        self,
        context: RequestContext,
        scope: Scope,
        web_acl_name: EntityName,
        web_acl_id: EntityId,
        rule_name: EntityName,
        rule_group_rule_name: EntityName = None,
    ) -> GetRateBasedStatementManagedKeysResponse:
        raise NotImplementedError

    @handler("GetRegexPatternSet")
    def get_regex_pattern_set(
        self, context: RequestContext, name: EntityName, scope: Scope, id: EntityId
    ) -> GetRegexPatternSetResponse:
        raise NotImplementedError

    @handler("GetRuleGroup")
    def get_rule_group(
        self,
        context: RequestContext,
        name: EntityName = None,
        scope: Scope = None,
        id: EntityId = None,
        arn: ResourceArn = None,
    ) -> GetRuleGroupResponse:
        raise NotImplementedError

    @handler("GetSampledRequests")
    def get_sampled_requests(
        self,
        context: RequestContext,
        web_acl_arn: ResourceArn,
        rule_metric_name: MetricName,
        scope: Scope,
        time_window: TimeWindow,
        max_items: ListMaxItems,
    ) -> GetSampledRequestsResponse:
        raise NotImplementedError

    @handler("GetWebACL")
    def get_web_acl(
        self, context: RequestContext, name: EntityName, scope: Scope, id: EntityId
    ) -> GetWebACLResponse:
        raise NotImplementedError

    @handler("GetWebACLForResource")
    def get_web_acl_for_resource(
        self, context: RequestContext, resource_arn: ResourceArn
    ) -> GetWebACLForResourceResponse:
        raise NotImplementedError

    @handler("ListAvailableManagedRuleGroupVersions")
    def list_available_managed_rule_group_versions(
        self,
        context: RequestContext,
        vendor_name: VendorName,
        name: EntityName,
        scope: Scope,
        next_marker: NextMarker = None,
        limit: PaginationLimit = None,
    ) -> ListAvailableManagedRuleGroupVersionsResponse:
        raise NotImplementedError

    @handler("ListAvailableManagedRuleGroups")
    def list_available_managed_rule_groups(
        self,
        context: RequestContext,
        scope: Scope,
        next_marker: NextMarker = None,
        limit: PaginationLimit = None,
    ) -> ListAvailableManagedRuleGroupsResponse:
        raise NotImplementedError

    @handler("ListIPSets")
    def list_ip_sets(
        self,
        context: RequestContext,
        scope: Scope,
        next_marker: NextMarker = None,
        limit: PaginationLimit = None,
    ) -> ListIPSetsResponse:
        raise NotImplementedError

    @handler("ListLoggingConfigurations")
    def list_logging_configurations(
        self,
        context: RequestContext,
        scope: Scope,
        next_marker: NextMarker = None,
        limit: PaginationLimit = None,
    ) -> ListLoggingConfigurationsResponse:
        raise NotImplementedError

    @handler("ListManagedRuleSets")
    def list_managed_rule_sets(
        self,
        context: RequestContext,
        scope: Scope,
        next_marker: NextMarker = None,
        limit: PaginationLimit = None,
    ) -> ListManagedRuleSetsResponse:
        raise NotImplementedError

    @handler("ListMobileSdkReleases")
    def list_mobile_sdk_releases(
        self,
        context: RequestContext,
        platform: Platform,
        next_marker: NextMarker = None,
        limit: PaginationLimit = None,
    ) -> ListMobileSdkReleasesResponse:
        raise NotImplementedError

    @handler("ListRegexPatternSets")
    def list_regex_pattern_sets(
        self,
        context: RequestContext,
        scope: Scope,
        next_marker: NextMarker = None,
        limit: PaginationLimit = None,
    ) -> ListRegexPatternSetsResponse:
        raise NotImplementedError

    @handler("ListResourcesForWebACL")
    def list_resources_for_web_acl(
        self, context: RequestContext, web_acl_arn: ResourceArn, resource_type: ResourceType = None
    ) -> ListResourcesForWebACLResponse:
        raise NotImplementedError

    @handler("ListRuleGroups")
    def list_rule_groups(
        self,
        context: RequestContext,
        scope: Scope,
        next_marker: NextMarker = None,
        limit: PaginationLimit = None,
    ) -> ListRuleGroupsResponse:
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
        self,
        context: RequestContext,
        scope: Scope,
        next_marker: NextMarker = None,
        limit: PaginationLimit = None,
    ) -> ListWebACLsResponse:
        raise NotImplementedError

    @handler("PutLoggingConfiguration")
    def put_logging_configuration(
        self, context: RequestContext, logging_configuration: LoggingConfiguration
    ) -> PutLoggingConfigurationResponse:
        raise NotImplementedError

    @handler("PutManagedRuleSetVersions")
    def put_managed_rule_set_versions(
        self,
        context: RequestContext,
        name: EntityName,
        scope: Scope,
        id: EntityId,
        lock_token: LockToken,
        recommended_version: VersionKeyString = None,
        versions_to_publish: VersionsToPublish = None,
    ) -> PutManagedRuleSetVersionsResponse:
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

    @handler("UpdateIPSet")
    def update_ip_set(
        self,
        context: RequestContext,
        name: EntityName,
        scope: Scope,
        id: EntityId,
        addresses: IPAddresses,
        lock_token: LockToken,
        description: EntityDescription = None,
    ) -> UpdateIPSetResponse:
        raise NotImplementedError

    @handler("UpdateManagedRuleSetVersionExpiryDate")
    def update_managed_rule_set_version_expiry_date(
        self,
        context: RequestContext,
        name: EntityName,
        scope: Scope,
        id: EntityId,
        lock_token: LockToken,
        version_to_expire: VersionKeyString,
        expiry_timestamp: Timestamp,
    ) -> UpdateManagedRuleSetVersionExpiryDateResponse:
        raise NotImplementedError

    @handler("UpdateRegexPatternSet")
    def update_regex_pattern_set(
        self,
        context: RequestContext,
        name: EntityName,
        scope: Scope,
        id: EntityId,
        regular_expression_list: RegularExpressionList,
        lock_token: LockToken,
        description: EntityDescription = None,
    ) -> UpdateRegexPatternSetResponse:
        raise NotImplementedError

    @handler("UpdateRuleGroup")
    def update_rule_group(
        self,
        context: RequestContext,
        name: EntityName,
        scope: Scope,
        id: EntityId,
        visibility_config: VisibilityConfig,
        lock_token: LockToken,
        description: EntityDescription = None,
        rules: Rules = None,
        custom_response_bodies: CustomResponseBodies = None,
    ) -> UpdateRuleGroupResponse:
        raise NotImplementedError

    @handler("UpdateWebACL")
    def update_web_acl(
        self,
        context: RequestContext,
        name: EntityName,
        scope: Scope,
        id: EntityId,
        default_action: DefaultAction,
        visibility_config: VisibilityConfig,
        lock_token: LockToken,
        description: EntityDescription = None,
        rules: Rules = None,
        custom_response_bodies: CustomResponseBodies = None,
        captcha_config: CaptchaConfig = None,
    ) -> UpdateWebACLResponse:
        raise NotImplementedError
