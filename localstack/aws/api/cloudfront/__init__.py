import sys
from datetime import datetime
from typing import List, Optional

if sys.version_info >= (3, 8):
    from typing import TypedDict
else:
    from typing_extensions import TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

CommentType = str
FunctionARN = str
FunctionName = str
LambdaFunctionARN = str
OriginShieldRegion = str
ResourceARN = str
TagKey = str
TagValue = str
aliasString = str
boolean = bool
distributionIdString = str
integer = int
listConflictingAliasesMaxItemsInteger = int
sensitiveStringType = str
string = str


class CachePolicyCookieBehavior(str):
    none = "none"
    whitelist = "whitelist"
    allExcept = "allExcept"
    all = "all"


class CachePolicyHeaderBehavior(str):
    none = "none"
    whitelist = "whitelist"


class CachePolicyQueryStringBehavior(str):
    none = "none"
    whitelist = "whitelist"
    allExcept = "allExcept"
    all = "all"


class CachePolicyType(str):
    managed = "managed"
    custom = "custom"


class CertificateSource(str):
    cloudfront = "cloudfront"
    iam = "iam"
    acm = "acm"


class EventType(str):
    viewer_request = "viewer-request"
    viewer_response = "viewer-response"
    origin_request = "origin-request"
    origin_response = "origin-response"


class Format(str):
    URLEncoded = "URLEncoded"


class FrameOptionsList(str):
    DENY = "DENY"
    SAMEORIGIN = "SAMEORIGIN"


class FunctionRuntime(str):
    cloudfront_js_1_0 = "cloudfront-js-1.0"


class FunctionStage(str):
    DEVELOPMENT = "DEVELOPMENT"
    LIVE = "LIVE"


class GeoRestrictionType(str):
    blacklist = "blacklist"
    whitelist = "whitelist"
    none = "none"


class HttpVersion(str):
    http1_1 = "http1.1"
    http2 = "http2"


class ICPRecordalStatus(str):
    APPROVED = "APPROVED"
    SUSPENDED = "SUSPENDED"
    PENDING = "PENDING"


class ItemSelection(str):
    none = "none"
    whitelist = "whitelist"
    all = "all"


class Method(str):
    GET = "GET"
    HEAD = "HEAD"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    OPTIONS = "OPTIONS"
    DELETE = "DELETE"


class MinimumProtocolVersion(str):
    SSLv3 = "SSLv3"
    TLSv1 = "TLSv1"
    TLSv1_2016 = "TLSv1_2016"
    TLSv1_1_2016 = "TLSv1.1_2016"
    TLSv1_2_2018 = "TLSv1.2_2018"
    TLSv1_2_2019 = "TLSv1.2_2019"
    TLSv1_2_2021 = "TLSv1.2_2021"


class OriginProtocolPolicy(str):
    http_only = "http-only"
    match_viewer = "match-viewer"
    https_only = "https-only"


class OriginRequestPolicyCookieBehavior(str):
    none = "none"
    whitelist = "whitelist"
    all = "all"


class OriginRequestPolicyHeaderBehavior(str):
    none = "none"
    whitelist = "whitelist"
    allViewer = "allViewer"
    allViewerAndWhitelistCloudFront = "allViewerAndWhitelistCloudFront"


class OriginRequestPolicyQueryStringBehavior(str):
    none = "none"
    whitelist = "whitelist"
    all = "all"


class OriginRequestPolicyType(str):
    managed = "managed"
    custom = "custom"


class PriceClass(str):
    PriceClass_100 = "PriceClass_100"
    PriceClass_200 = "PriceClass_200"
    PriceClass_All = "PriceClass_All"


class RealtimeMetricsSubscriptionStatus(str):
    Enabled = "Enabled"
    Disabled = "Disabled"


class ReferrerPolicyList(str):
    no_referrer = "no-referrer"
    no_referrer_when_downgrade = "no-referrer-when-downgrade"
    origin = "origin"
    origin_when_cross_origin = "origin-when-cross-origin"
    same_origin = "same-origin"
    strict_origin = "strict-origin"
    strict_origin_when_cross_origin = "strict-origin-when-cross-origin"
    unsafe_url = "unsafe-url"


class ResponseHeadersPolicyAccessControlAllowMethodsValues(str):
    GET = "GET"
    POST = "POST"
    OPTIONS = "OPTIONS"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"
    HEAD = "HEAD"
    ALL = "ALL"


class ResponseHeadersPolicyType(str):
    managed = "managed"
    custom = "custom"


class SSLSupportMethod(str):
    sni_only = "sni-only"
    vip = "vip"
    static_ip = "static-ip"


class SslProtocol(str):
    SSLv3 = "SSLv3"
    TLSv1 = "TLSv1"
    TLSv1_1 = "TLSv1.1"
    TLSv1_2 = "TLSv1.2"


class ViewerProtocolPolicy(str):
    allow_all = "allow-all"
    https_only = "https-only"
    redirect_to_https = "redirect-to-https"


class AccessDenied(ServiceException):
    Message: Optional[string]


class BatchTooLarge(ServiceException):
    Message: Optional[string]


class CNAMEAlreadyExists(ServiceException):
    Message: Optional[string]


class CachePolicyAlreadyExists(ServiceException):
    Message: Optional[string]


class CachePolicyInUse(ServiceException):
    Message: Optional[string]


class CannotChangeImmutablePublicKeyFields(ServiceException):
    Message: Optional[string]


class CloudFrontOriginAccessIdentityAlreadyExists(ServiceException):
    Message: Optional[string]


class CloudFrontOriginAccessIdentityInUse(ServiceException):
    Message: Optional[string]


class DistributionAlreadyExists(ServiceException):
    Message: Optional[string]


class DistributionNotDisabled(ServiceException):
    Message: Optional[string]


class FieldLevelEncryptionConfigAlreadyExists(ServiceException):
    Message: Optional[string]


class FieldLevelEncryptionConfigInUse(ServiceException):
    Message: Optional[string]


class FieldLevelEncryptionProfileAlreadyExists(ServiceException):
    Message: Optional[string]


class FieldLevelEncryptionProfileInUse(ServiceException):
    Message: Optional[string]


class FieldLevelEncryptionProfileSizeExceeded(ServiceException):
    Message: Optional[string]


class FunctionAlreadyExists(ServiceException):
    Message: Optional[string]


class FunctionInUse(ServiceException):
    Message: Optional[string]


class FunctionSizeLimitExceeded(ServiceException):
    Message: Optional[string]


class IllegalDelete(ServiceException):
    Message: Optional[string]


class IllegalFieldLevelEncryptionConfigAssociationWithCacheBehavior(ServiceException):
    Message: Optional[string]


class IllegalUpdate(ServiceException):
    Message: Optional[string]


class InconsistentQuantities(ServiceException):
    Message: Optional[string]


class InvalidArgument(ServiceException):
    Message: Optional[string]


class InvalidDefaultRootObject(ServiceException):
    Message: Optional[string]


class InvalidErrorCode(ServiceException):
    Message: Optional[string]


class InvalidForwardCookies(ServiceException):
    Message: Optional[string]


class InvalidFunctionAssociation(ServiceException):
    Message: Optional[string]


class InvalidGeoRestrictionParameter(ServiceException):
    Message: Optional[string]


class InvalidHeadersForS3Origin(ServiceException):
    Message: Optional[string]


class InvalidIfMatchVersion(ServiceException):
    Message: Optional[string]


class InvalidLambdaFunctionAssociation(ServiceException):
    Message: Optional[string]


class InvalidLocationCode(ServiceException):
    Message: Optional[string]


class InvalidMinimumProtocolVersion(ServiceException):
    Message: Optional[string]


class InvalidOrigin(ServiceException):
    Message: Optional[string]


class InvalidOriginAccessIdentity(ServiceException):
    Message: Optional[string]


class InvalidOriginKeepaliveTimeout(ServiceException):
    Message: Optional[string]


class InvalidOriginReadTimeout(ServiceException):
    Message: Optional[string]


class InvalidProtocolSettings(ServiceException):
    Message: Optional[string]


class InvalidQueryStringParameters(ServiceException):
    Message: Optional[string]


class InvalidRelativePath(ServiceException):
    Message: Optional[string]


class InvalidRequiredProtocol(ServiceException):
    Message: Optional[string]


class InvalidResponseCode(ServiceException):
    Message: Optional[string]


class InvalidTTLOrder(ServiceException):
    Message: Optional[string]


class InvalidTagging(ServiceException):
    Message: Optional[string]


class InvalidViewerCertificate(ServiceException):
    Message: Optional[string]


class InvalidWebACLId(ServiceException):
    Message: Optional[string]


class KeyGroupAlreadyExists(ServiceException):
    Message: Optional[string]


class MissingBody(ServiceException):
    Message: Optional[string]


class NoSuchCachePolicy(ServiceException):
    Message: Optional[string]


class NoSuchCloudFrontOriginAccessIdentity(ServiceException):
    Message: Optional[string]


class NoSuchDistribution(ServiceException):
    Message: Optional[string]


class NoSuchFieldLevelEncryptionConfig(ServiceException):
    Message: Optional[string]


class NoSuchFieldLevelEncryptionProfile(ServiceException):
    Message: Optional[string]


class NoSuchFunctionExists(ServiceException):
    Message: Optional[string]


class NoSuchInvalidation(ServiceException):
    Message: Optional[string]


class NoSuchOrigin(ServiceException):
    Message: Optional[string]


class NoSuchOriginRequestPolicy(ServiceException):
    Message: Optional[string]


class NoSuchPublicKey(ServiceException):
    Message: Optional[string]


class NoSuchRealtimeLogConfig(ServiceException):
    Message: Optional[string]


class NoSuchResource(ServiceException):
    Message: Optional[string]


class NoSuchResponseHeadersPolicy(ServiceException):
    Message: Optional[string]


class NoSuchStreamingDistribution(ServiceException):
    Message: Optional[string]


class OriginRequestPolicyAlreadyExists(ServiceException):
    Message: Optional[string]


class OriginRequestPolicyInUse(ServiceException):
    Message: Optional[string]


class PreconditionFailed(ServiceException):
    Message: Optional[string]


class PublicKeyAlreadyExists(ServiceException):
    Message: Optional[string]


class PublicKeyInUse(ServiceException):
    Message: Optional[string]


class QueryArgProfileEmpty(ServiceException):
    Message: Optional[string]


class RealtimeLogConfigAlreadyExists(ServiceException):
    Message: Optional[string]


class RealtimeLogConfigInUse(ServiceException):
    Message: Optional[string]


class RealtimeLogConfigOwnerMismatch(ServiceException):
    Message: Optional[string]


class ResourceInUse(ServiceException):
    Message: Optional[string]


class ResponseHeadersPolicyAlreadyExists(ServiceException):
    Message: Optional[string]


class ResponseHeadersPolicyInUse(ServiceException):
    Message: Optional[string]


class StreamingDistributionAlreadyExists(ServiceException):
    Message: Optional[string]


class StreamingDistributionNotDisabled(ServiceException):
    Message: Optional[string]


class TestFunctionFailed(ServiceException):
    Message: Optional[string]


class TooManyCacheBehaviors(ServiceException):
    Message: Optional[string]


class TooManyCachePolicies(ServiceException):
    Message: Optional[string]


class TooManyCertificates(ServiceException):
    Message: Optional[string]


class TooManyCloudFrontOriginAccessIdentities(ServiceException):
    Message: Optional[string]


class TooManyCookieNamesInWhiteList(ServiceException):
    Message: Optional[string]


class TooManyCookiesInCachePolicy(ServiceException):
    Message: Optional[string]


class TooManyCookiesInOriginRequestPolicy(ServiceException):
    Message: Optional[string]


class TooManyCustomHeadersInResponseHeadersPolicy(ServiceException):
    Message: Optional[string]


class TooManyDistributionCNAMEs(ServiceException):
    Message: Optional[string]


class TooManyDistributions(ServiceException):
    Message: Optional[string]


class TooManyDistributionsAssociatedToCachePolicy(ServiceException):
    Message: Optional[string]


class TooManyDistributionsAssociatedToFieldLevelEncryptionConfig(ServiceException):
    Message: Optional[string]


class TooManyDistributionsAssociatedToKeyGroup(ServiceException):
    Message: Optional[string]


class TooManyDistributionsAssociatedToOriginRequestPolicy(ServiceException):
    Message: Optional[string]


class TooManyDistributionsAssociatedToResponseHeadersPolicy(ServiceException):
    Message: Optional[string]


class TooManyDistributionsWithFunctionAssociations(ServiceException):
    Message: Optional[string]


class TooManyDistributionsWithLambdaAssociations(ServiceException):
    Message: Optional[string]


class TooManyDistributionsWithSingleFunctionARN(ServiceException):
    Message: Optional[string]


class TooManyFieldLevelEncryptionConfigs(ServiceException):
    Message: Optional[string]


class TooManyFieldLevelEncryptionContentTypeProfiles(ServiceException):
    Message: Optional[string]


class TooManyFieldLevelEncryptionEncryptionEntities(ServiceException):
    Message: Optional[string]


class TooManyFieldLevelEncryptionFieldPatterns(ServiceException):
    Message: Optional[string]


class TooManyFieldLevelEncryptionProfiles(ServiceException):
    Message: Optional[string]


class TooManyFieldLevelEncryptionQueryArgProfiles(ServiceException):
    Message: Optional[string]


class TooManyFunctionAssociations(ServiceException):
    Message: Optional[string]


class TooManyFunctions(ServiceException):
    Message: Optional[string]


class TooManyHeadersInCachePolicy(ServiceException):
    Message: Optional[string]


class TooManyHeadersInForwardedValues(ServiceException):
    Message: Optional[string]


class TooManyHeadersInOriginRequestPolicy(ServiceException):
    Message: Optional[string]


class TooManyInvalidationsInProgress(ServiceException):
    Message: Optional[string]


class TooManyKeyGroups(ServiceException):
    Message: Optional[string]


class TooManyKeyGroupsAssociatedToDistribution(ServiceException):
    Message: Optional[string]


class TooManyLambdaFunctionAssociations(ServiceException):
    Message: Optional[string]


class TooManyOriginCustomHeaders(ServiceException):
    Message: Optional[string]


class TooManyOriginGroupsPerDistribution(ServiceException):
    Message: Optional[string]


class TooManyOriginRequestPolicies(ServiceException):
    Message: Optional[string]


class TooManyOrigins(ServiceException):
    Message: Optional[string]


class TooManyPublicKeys(ServiceException):
    Message: Optional[string]


class TooManyPublicKeysInKeyGroup(ServiceException):
    Message: Optional[string]


class TooManyQueryStringParameters(ServiceException):
    Message: Optional[string]


class TooManyQueryStringsInCachePolicy(ServiceException):
    Message: Optional[string]


class TooManyQueryStringsInOriginRequestPolicy(ServiceException):
    Message: Optional[string]


class TooManyRealtimeLogConfigs(ServiceException):
    Message: Optional[string]


class TooManyResponseHeadersPolicies(ServiceException):
    Message: Optional[string]


class TooManyStreamingDistributionCNAMEs(ServiceException):
    Message: Optional[string]


class TooManyStreamingDistributions(ServiceException):
    Message: Optional[string]


class TooManyTrustedSigners(ServiceException):
    Message: Optional[string]


class TrustedKeyGroupDoesNotExist(ServiceException):
    Message: Optional[string]


class TrustedSignerDoesNotExist(ServiceException):
    Message: Optional[string]


class UnsupportedOperation(ServiceException):
    Message: Optional[string]


AccessControlAllowHeadersList = List[string]
AccessControlAllowMethodsList = List[ResponseHeadersPolicyAccessControlAllowMethodsValues]
AccessControlAllowOriginsList = List[string]
AccessControlExposeHeadersList = List[string]
KeyPairIdList = List[string]


class KeyPairIds(TypedDict, total=False):
    Quantity: integer
    Items: Optional[KeyPairIdList]


class KGKeyPairIds(TypedDict, total=False):
    KeyGroupId: Optional[string]
    KeyPairIds: Optional[KeyPairIds]


KGKeyPairIdsList = List[KGKeyPairIds]


class ActiveTrustedKeyGroups(TypedDict, total=False):
    Enabled: boolean
    Quantity: integer
    Items: Optional[KGKeyPairIdsList]


class Signer(TypedDict, total=False):
    AwsAccountNumber: Optional[string]
    KeyPairIds: Optional[KeyPairIds]


SignerList = List[Signer]


class ActiveTrustedSigners(TypedDict, total=False):
    Enabled: boolean
    Quantity: integer
    Items: Optional[SignerList]


class AliasICPRecordal(TypedDict, total=False):
    CNAME: Optional[string]
    ICPRecordalStatus: Optional[ICPRecordalStatus]


AliasICPRecordals = List[AliasICPRecordal]
AliasList = List[string]


class Aliases(TypedDict, total=False):
    Quantity: integer
    Items: Optional[AliasList]


MethodsList = List[Method]


class CachedMethods(TypedDict, total=False):
    Quantity: integer
    Items: MethodsList


class AllowedMethods(TypedDict, total=False):
    Quantity: integer
    Items: MethodsList
    CachedMethods: Optional[CachedMethods]


class AssociateAliasRequest(ServiceRequest):
    TargetDistributionId: string
    Alias: string


AwsAccountNumberList = List[string]
long = int
QueryStringCacheKeysList = List[string]


class QueryStringCacheKeys(TypedDict, total=False):
    Quantity: integer
    Items: Optional[QueryStringCacheKeysList]


HeaderList = List[string]


class Headers(TypedDict, total=False):
    Quantity: integer
    Items: Optional[HeaderList]


CookieNameList = List[string]


class CookieNames(TypedDict, total=False):
    Quantity: integer
    Items: Optional[CookieNameList]


class CookiePreference(TypedDict, total=False):
    Forward: ItemSelection
    WhitelistedNames: Optional[CookieNames]


class ForwardedValues(TypedDict, total=False):
    QueryString: boolean
    Cookies: CookiePreference
    Headers: Optional[Headers]
    QueryStringCacheKeys: Optional[QueryStringCacheKeys]


class FunctionAssociation(TypedDict, total=False):
    FunctionARN: FunctionARN
    EventType: EventType


FunctionAssociationList = List[FunctionAssociation]


class FunctionAssociations(TypedDict, total=False):
    Quantity: integer
    Items: Optional[FunctionAssociationList]


class LambdaFunctionAssociation(TypedDict, total=False):
    LambdaFunctionARN: LambdaFunctionARN
    EventType: EventType
    IncludeBody: Optional[boolean]


LambdaFunctionAssociationList = List[LambdaFunctionAssociation]


class LambdaFunctionAssociations(TypedDict, total=False):
    Quantity: integer
    Items: Optional[LambdaFunctionAssociationList]


TrustedKeyGroupIdList = List[string]


class TrustedKeyGroups(TypedDict, total=False):
    Enabled: boolean
    Quantity: integer
    Items: Optional[TrustedKeyGroupIdList]


class TrustedSigners(TypedDict, total=False):
    Enabled: boolean
    Quantity: integer
    Items: Optional[AwsAccountNumberList]


class CacheBehavior(TypedDict, total=False):
    PathPattern: string
    TargetOriginId: string
    TrustedSigners: Optional[TrustedSigners]
    TrustedKeyGroups: Optional[TrustedKeyGroups]
    ViewerProtocolPolicy: ViewerProtocolPolicy
    AllowedMethods: Optional[AllowedMethods]
    SmoothStreaming: Optional[boolean]
    Compress: Optional[boolean]
    LambdaFunctionAssociations: Optional[LambdaFunctionAssociations]
    FunctionAssociations: Optional[FunctionAssociations]
    FieldLevelEncryptionId: Optional[string]
    RealtimeLogConfigArn: Optional[string]
    CachePolicyId: Optional[string]
    OriginRequestPolicyId: Optional[string]
    ResponseHeadersPolicyId: Optional[string]
    ForwardedValues: Optional[ForwardedValues]
    MinTTL: Optional[long]
    DefaultTTL: Optional[long]
    MaxTTL: Optional[long]


CacheBehaviorList = List[CacheBehavior]


class CacheBehaviors(TypedDict, total=False):
    Quantity: integer
    Items: Optional[CacheBehaviorList]


QueryStringNamesList = List[string]


class QueryStringNames(TypedDict, total=False):
    Quantity: integer
    Items: Optional[QueryStringNamesList]


class CachePolicyQueryStringsConfig(TypedDict, total=False):
    QueryStringBehavior: CachePolicyQueryStringBehavior
    QueryStrings: Optional[QueryStringNames]


class CachePolicyCookiesConfig(TypedDict, total=False):
    CookieBehavior: CachePolicyCookieBehavior
    Cookies: Optional[CookieNames]


class CachePolicyHeadersConfig(TypedDict, total=False):
    HeaderBehavior: CachePolicyHeaderBehavior
    Headers: Optional[Headers]


class ParametersInCacheKeyAndForwardedToOrigin(TypedDict, total=False):
    EnableAcceptEncodingGzip: boolean
    EnableAcceptEncodingBrotli: Optional[boolean]
    HeadersConfig: CachePolicyHeadersConfig
    CookiesConfig: CachePolicyCookiesConfig
    QueryStringsConfig: CachePolicyQueryStringsConfig


class CachePolicyConfig(TypedDict, total=False):
    Comment: Optional[string]
    Name: string
    DefaultTTL: Optional[long]
    MaxTTL: Optional[long]
    MinTTL: long
    ParametersInCacheKeyAndForwardedToOrigin: Optional[ParametersInCacheKeyAndForwardedToOrigin]


timestamp = datetime


class CachePolicy(TypedDict, total=False):
    Id: string
    LastModifiedTime: timestamp
    CachePolicyConfig: CachePolicyConfig


class CachePolicySummary(TypedDict, total=False):
    Type: CachePolicyType
    CachePolicy: CachePolicy


CachePolicySummaryList = List[CachePolicySummary]


class CachePolicyList(TypedDict, total=False):
    NextMarker: Optional[string]
    MaxItems: integer
    Quantity: integer
    Items: Optional[CachePolicySummaryList]


class CloudFrontOriginAccessIdentityConfig(TypedDict, total=False):
    CallerReference: string
    Comment: string


class CloudFrontOriginAccessIdentity(TypedDict, total=False):
    Id: string
    S3CanonicalUserId: string
    CloudFrontOriginAccessIdentityConfig: Optional[CloudFrontOriginAccessIdentityConfig]


class CloudFrontOriginAccessIdentitySummary(TypedDict, total=False):
    Id: string
    S3CanonicalUserId: string
    Comment: string


CloudFrontOriginAccessIdentitySummaryList = List[CloudFrontOriginAccessIdentitySummary]


class CloudFrontOriginAccessIdentityList(TypedDict, total=False):
    Marker: string
    NextMarker: Optional[string]
    MaxItems: integer
    IsTruncated: boolean
    Quantity: integer
    Items: Optional[CloudFrontOriginAccessIdentitySummaryList]


class ConflictingAlias(TypedDict, total=False):
    Alias: Optional[string]
    DistributionId: Optional[string]
    AccountId: Optional[string]


ConflictingAliases = List[ConflictingAlias]


class ConflictingAliasesList(TypedDict, total=False):
    NextMarker: Optional[string]
    MaxItems: Optional[integer]
    Quantity: Optional[integer]
    Items: Optional[ConflictingAliases]


class ContentTypeProfile(TypedDict, total=False):
    Format: Format
    ProfileId: Optional[string]
    ContentType: string


ContentTypeProfileList = List[ContentTypeProfile]


class ContentTypeProfiles(TypedDict, total=False):
    Quantity: integer
    Items: Optional[ContentTypeProfileList]


class ContentTypeProfileConfig(TypedDict, total=False):
    ForwardWhenContentTypeIsUnknown: boolean
    ContentTypeProfiles: Optional[ContentTypeProfiles]


class CreateCachePolicyRequest(ServiceRequest):
    CachePolicyConfig: CachePolicyConfig


class CreateCachePolicyResult(TypedDict, total=False):
    CachePolicy: Optional[CachePolicy]
    Location: Optional[string]
    ETag: Optional[string]


class CreateCloudFrontOriginAccessIdentityRequest(ServiceRequest):
    CloudFrontOriginAccessIdentityConfig: CloudFrontOriginAccessIdentityConfig


class CreateCloudFrontOriginAccessIdentityResult(TypedDict, total=False):
    CloudFrontOriginAccessIdentity: Optional[CloudFrontOriginAccessIdentity]
    Location: Optional[string]
    ETag: Optional[string]


LocationList = List[string]


class GeoRestriction(TypedDict, total=False):
    RestrictionType: GeoRestrictionType
    Quantity: integer
    Items: Optional[LocationList]


class Restrictions(TypedDict, total=False):
    GeoRestriction: GeoRestriction


class ViewerCertificate(TypedDict, total=False):
    CloudFrontDefaultCertificate: Optional[boolean]
    IAMCertificateId: Optional[string]
    ACMCertificateArn: Optional[string]
    SSLSupportMethod: Optional[SSLSupportMethod]
    MinimumProtocolVersion: Optional[MinimumProtocolVersion]
    Certificate: Optional[string]
    CertificateSource: Optional[CertificateSource]


class LoggingConfig(TypedDict, total=False):
    Enabled: boolean
    IncludeCookies: boolean
    Bucket: string
    Prefix: string


class CustomErrorResponse(TypedDict, total=False):
    ErrorCode: integer
    ResponsePagePath: Optional[string]
    ResponseCode: Optional[string]
    ErrorCachingMinTTL: Optional[long]


CustomErrorResponseList = List[CustomErrorResponse]


class CustomErrorResponses(TypedDict, total=False):
    Quantity: integer
    Items: Optional[CustomErrorResponseList]


class DefaultCacheBehavior(TypedDict, total=False):
    TargetOriginId: string
    TrustedSigners: Optional[TrustedSigners]
    TrustedKeyGroups: Optional[TrustedKeyGroups]
    ViewerProtocolPolicy: ViewerProtocolPolicy
    AllowedMethods: Optional[AllowedMethods]
    SmoothStreaming: Optional[boolean]
    Compress: Optional[boolean]
    LambdaFunctionAssociations: Optional[LambdaFunctionAssociations]
    FunctionAssociations: Optional[FunctionAssociations]
    FieldLevelEncryptionId: Optional[string]
    RealtimeLogConfigArn: Optional[string]
    CachePolicyId: Optional[string]
    OriginRequestPolicyId: Optional[string]
    ResponseHeadersPolicyId: Optional[string]
    ForwardedValues: Optional[ForwardedValues]
    MinTTL: Optional[long]
    DefaultTTL: Optional[long]
    MaxTTL: Optional[long]


class OriginGroupMember(TypedDict, total=False):
    OriginId: string


OriginGroupMemberList = List[OriginGroupMember]


class OriginGroupMembers(TypedDict, total=False):
    Quantity: integer
    Items: OriginGroupMemberList


StatusCodeList = List[integer]


class StatusCodes(TypedDict, total=False):
    Quantity: integer
    Items: StatusCodeList


class OriginGroupFailoverCriteria(TypedDict, total=False):
    StatusCodes: StatusCodes


class OriginGroup(TypedDict, total=False):
    Id: string
    FailoverCriteria: OriginGroupFailoverCriteria
    Members: OriginGroupMembers


OriginGroupList = List[OriginGroup]


class OriginGroups(TypedDict, total=False):
    Quantity: integer
    Items: Optional[OriginGroupList]


class OriginShield(TypedDict, total=False):
    Enabled: boolean
    OriginShieldRegion: Optional[OriginShieldRegion]


SslProtocolsList = List[SslProtocol]


class OriginSslProtocols(TypedDict, total=False):
    Quantity: integer
    Items: SslProtocolsList


class CustomOriginConfig(TypedDict, total=False):
    HTTPPort: integer
    HTTPSPort: integer
    OriginProtocolPolicy: OriginProtocolPolicy
    OriginSslProtocols: Optional[OriginSslProtocols]
    OriginReadTimeout: Optional[integer]
    OriginKeepaliveTimeout: Optional[integer]


class S3OriginConfig(TypedDict, total=False):
    OriginAccessIdentity: string


class OriginCustomHeader(TypedDict, total=False):
    HeaderName: string
    HeaderValue: sensitiveStringType


OriginCustomHeadersList = List[OriginCustomHeader]


class CustomHeaders(TypedDict, total=False):
    Quantity: integer
    Items: Optional[OriginCustomHeadersList]


class Origin(TypedDict, total=False):
    Id: string
    DomainName: string
    OriginPath: Optional[string]
    CustomHeaders: Optional[CustomHeaders]
    S3OriginConfig: Optional[S3OriginConfig]
    CustomOriginConfig: Optional[CustomOriginConfig]
    ConnectionAttempts: Optional[integer]
    ConnectionTimeout: Optional[integer]
    OriginShield: Optional[OriginShield]


OriginList = List[Origin]


class Origins(TypedDict, total=False):
    Quantity: integer
    Items: OriginList


class DistributionConfig(TypedDict, total=False):
    CallerReference: string
    Aliases: Optional[Aliases]
    DefaultRootObject: Optional[string]
    Origins: Origins
    OriginGroups: Optional[OriginGroups]
    DefaultCacheBehavior: DefaultCacheBehavior
    CacheBehaviors: Optional[CacheBehaviors]
    CustomErrorResponses: Optional[CustomErrorResponses]
    Comment: CommentType
    Logging: Optional[LoggingConfig]
    PriceClass: Optional[PriceClass]
    Enabled: boolean
    ViewerCertificate: Optional[ViewerCertificate]
    Restrictions: Optional[Restrictions]
    WebACLId: Optional[string]
    HttpVersion: Optional[HttpVersion]
    IsIPV6Enabled: Optional[boolean]


class CreateDistributionRequest(ServiceRequest):
    DistributionConfig: DistributionConfig


class Distribution(TypedDict, total=False):
    Id: string
    ARN: string
    Status: string
    LastModifiedTime: timestamp
    InProgressInvalidationBatches: integer
    DomainName: string
    ActiveTrustedSigners: Optional[ActiveTrustedSigners]
    ActiveTrustedKeyGroups: Optional[ActiveTrustedKeyGroups]
    DistributionConfig: DistributionConfig
    AliasICPRecordals: Optional[AliasICPRecordals]


class CreateDistributionResult(TypedDict, total=False):
    Distribution: Optional[Distribution]
    Location: Optional[string]
    ETag: Optional[string]


class Tag(TypedDict, total=False):
    Key: TagKey
    Value: Optional[TagValue]


TagList = List[Tag]


class Tags(TypedDict, total=False):
    Items: Optional[TagList]


class DistributionConfigWithTags(TypedDict, total=False):
    DistributionConfig: DistributionConfig
    Tags: Tags


class CreateDistributionWithTagsRequest(ServiceRequest):
    DistributionConfigWithTags: DistributionConfigWithTags


class CreateDistributionWithTagsResult(TypedDict, total=False):
    Distribution: Optional[Distribution]
    Location: Optional[string]
    ETag: Optional[string]


class QueryArgProfile(TypedDict, total=False):
    QueryArg: string
    ProfileId: string


QueryArgProfileList = List[QueryArgProfile]


class QueryArgProfiles(TypedDict, total=False):
    Quantity: integer
    Items: Optional[QueryArgProfileList]


class QueryArgProfileConfig(TypedDict, total=False):
    ForwardWhenQueryArgProfileIsUnknown: boolean
    QueryArgProfiles: Optional[QueryArgProfiles]


class FieldLevelEncryptionConfig(TypedDict, total=False):
    CallerReference: string
    Comment: Optional[string]
    QueryArgProfileConfig: Optional[QueryArgProfileConfig]
    ContentTypeProfileConfig: Optional[ContentTypeProfileConfig]


class CreateFieldLevelEncryptionConfigRequest(ServiceRequest):
    FieldLevelEncryptionConfig: FieldLevelEncryptionConfig


class FieldLevelEncryption(TypedDict, total=False):
    Id: string
    LastModifiedTime: timestamp
    FieldLevelEncryptionConfig: FieldLevelEncryptionConfig


class CreateFieldLevelEncryptionConfigResult(TypedDict, total=False):
    FieldLevelEncryption: Optional[FieldLevelEncryption]
    Location: Optional[string]
    ETag: Optional[string]


FieldPatternList = List[string]


class FieldPatterns(TypedDict, total=False):
    Quantity: integer
    Items: Optional[FieldPatternList]


class EncryptionEntity(TypedDict, total=False):
    PublicKeyId: string
    ProviderId: string
    FieldPatterns: FieldPatterns


EncryptionEntityList = List[EncryptionEntity]


class EncryptionEntities(TypedDict, total=False):
    Quantity: integer
    Items: Optional[EncryptionEntityList]


class FieldLevelEncryptionProfileConfig(TypedDict, total=False):
    Name: string
    CallerReference: string
    Comment: Optional[string]
    EncryptionEntities: EncryptionEntities


class CreateFieldLevelEncryptionProfileRequest(ServiceRequest):
    FieldLevelEncryptionProfileConfig: FieldLevelEncryptionProfileConfig


class FieldLevelEncryptionProfile(TypedDict, total=False):
    Id: string
    LastModifiedTime: timestamp
    FieldLevelEncryptionProfileConfig: FieldLevelEncryptionProfileConfig


class CreateFieldLevelEncryptionProfileResult(TypedDict, total=False):
    FieldLevelEncryptionProfile: Optional[FieldLevelEncryptionProfile]
    Location: Optional[string]
    ETag: Optional[string]


FunctionBlob = bytes


class FunctionConfig(TypedDict, total=False):
    Comment: string
    Runtime: FunctionRuntime


class CreateFunctionRequest(ServiceRequest):
    Name: FunctionName
    FunctionConfig: FunctionConfig
    FunctionCode: FunctionBlob


class FunctionMetadata(TypedDict, total=False):
    FunctionARN: string
    Stage: Optional[FunctionStage]
    CreatedTime: Optional[timestamp]
    LastModifiedTime: timestamp


class FunctionSummary(TypedDict, total=False):
    Name: FunctionName
    Status: Optional[string]
    FunctionConfig: FunctionConfig
    FunctionMetadata: FunctionMetadata


class CreateFunctionResult(TypedDict, total=False):
    FunctionSummary: Optional[FunctionSummary]
    Location: Optional[string]
    ETag: Optional[string]


PathList = List[string]


class Paths(TypedDict, total=False):
    Quantity: integer
    Items: Optional[PathList]


class InvalidationBatch(TypedDict, total=False):
    Paths: Paths
    CallerReference: string


class CreateInvalidationRequest(ServiceRequest):
    DistributionId: string
    InvalidationBatch: InvalidationBatch


class Invalidation(TypedDict, total=False):
    Id: string
    Status: string
    CreateTime: timestamp
    InvalidationBatch: InvalidationBatch


class CreateInvalidationResult(TypedDict, total=False):
    Location: Optional[string]
    Invalidation: Optional[Invalidation]


PublicKeyIdList = List[string]


class KeyGroupConfig(TypedDict, total=False):
    Name: string
    Items: PublicKeyIdList
    Comment: Optional[string]


class CreateKeyGroupRequest(ServiceRequest):
    KeyGroupConfig: KeyGroupConfig


class KeyGroup(TypedDict, total=False):
    Id: string
    LastModifiedTime: timestamp
    KeyGroupConfig: KeyGroupConfig


class CreateKeyGroupResult(TypedDict, total=False):
    KeyGroup: Optional[KeyGroup]
    Location: Optional[string]
    ETag: Optional[string]


class RealtimeMetricsSubscriptionConfig(TypedDict, total=False):
    RealtimeMetricsSubscriptionStatus: RealtimeMetricsSubscriptionStatus


class MonitoringSubscription(TypedDict, total=False):
    RealtimeMetricsSubscriptionConfig: Optional[RealtimeMetricsSubscriptionConfig]


class CreateMonitoringSubscriptionRequest(ServiceRequest):
    DistributionId: string
    MonitoringSubscription: MonitoringSubscription


class CreateMonitoringSubscriptionResult(TypedDict, total=False):
    MonitoringSubscription: Optional[MonitoringSubscription]


class OriginRequestPolicyQueryStringsConfig(TypedDict, total=False):
    QueryStringBehavior: OriginRequestPolicyQueryStringBehavior
    QueryStrings: Optional[QueryStringNames]


class OriginRequestPolicyCookiesConfig(TypedDict, total=False):
    CookieBehavior: OriginRequestPolicyCookieBehavior
    Cookies: Optional[CookieNames]


class OriginRequestPolicyHeadersConfig(TypedDict, total=False):
    HeaderBehavior: OriginRequestPolicyHeaderBehavior
    Headers: Optional[Headers]


class OriginRequestPolicyConfig(TypedDict, total=False):
    Comment: Optional[string]
    Name: string
    HeadersConfig: OriginRequestPolicyHeadersConfig
    CookiesConfig: OriginRequestPolicyCookiesConfig
    QueryStringsConfig: OriginRequestPolicyQueryStringsConfig


class CreateOriginRequestPolicyRequest(ServiceRequest):
    OriginRequestPolicyConfig: OriginRequestPolicyConfig


class OriginRequestPolicy(TypedDict, total=False):
    Id: string
    LastModifiedTime: timestamp
    OriginRequestPolicyConfig: OriginRequestPolicyConfig


class CreateOriginRequestPolicyResult(TypedDict, total=False):
    OriginRequestPolicy: Optional[OriginRequestPolicy]
    Location: Optional[string]
    ETag: Optional[string]


class PublicKeyConfig(TypedDict, total=False):
    CallerReference: string
    Name: string
    EncodedKey: string
    Comment: Optional[string]


class CreatePublicKeyRequest(ServiceRequest):
    PublicKeyConfig: PublicKeyConfig


class PublicKey(TypedDict, total=False):
    Id: string
    CreatedTime: timestamp
    PublicKeyConfig: PublicKeyConfig


class CreatePublicKeyResult(TypedDict, total=False):
    PublicKey: Optional[PublicKey]
    Location: Optional[string]
    ETag: Optional[string]


FieldList = List[string]


class KinesisStreamConfig(TypedDict, total=False):
    RoleARN: string
    StreamARN: string


class EndPoint(TypedDict, total=False):
    StreamType: string
    KinesisStreamConfig: Optional[KinesisStreamConfig]


EndPointList = List[EndPoint]


class CreateRealtimeLogConfigRequest(ServiceRequest):
    EndPoints: EndPointList
    Fields: FieldList
    Name: string
    SamplingRate: long


class RealtimeLogConfig(TypedDict, total=False):
    ARN: string
    Name: string
    SamplingRate: long
    EndPoints: EndPointList
    Fields: FieldList


class CreateRealtimeLogConfigResult(TypedDict, total=False):
    RealtimeLogConfig: Optional[RealtimeLogConfig]


class ResponseHeadersPolicyCustomHeader(TypedDict, total=False):
    Header: string
    Value: string
    Override: boolean


ResponseHeadersPolicyCustomHeaderList = List[ResponseHeadersPolicyCustomHeader]


class ResponseHeadersPolicyCustomHeadersConfig(TypedDict, total=False):
    Quantity: integer
    Items: Optional[ResponseHeadersPolicyCustomHeaderList]


class ResponseHeadersPolicyStrictTransportSecurity(TypedDict, total=False):
    Override: boolean
    IncludeSubdomains: Optional[boolean]
    Preload: Optional[boolean]
    AccessControlMaxAgeSec: integer


class ResponseHeadersPolicyContentTypeOptions(TypedDict, total=False):
    Override: boolean


class ResponseHeadersPolicyContentSecurityPolicy(TypedDict, total=False):
    Override: boolean
    ContentSecurityPolicy: string


class ResponseHeadersPolicyReferrerPolicy(TypedDict, total=False):
    Override: boolean
    ReferrerPolicy: ReferrerPolicyList


class ResponseHeadersPolicyFrameOptions(TypedDict, total=False):
    Override: boolean
    FrameOption: FrameOptionsList


class ResponseHeadersPolicyXSSProtection(TypedDict, total=False):
    Override: boolean
    Protection: boolean
    ModeBlock: Optional[boolean]
    ReportUri: Optional[string]


class ResponseHeadersPolicySecurityHeadersConfig(TypedDict, total=False):
    XSSProtection: Optional[ResponseHeadersPolicyXSSProtection]
    FrameOptions: Optional[ResponseHeadersPolicyFrameOptions]
    ReferrerPolicy: Optional[ResponseHeadersPolicyReferrerPolicy]
    ContentSecurityPolicy: Optional[ResponseHeadersPolicyContentSecurityPolicy]
    ContentTypeOptions: Optional[ResponseHeadersPolicyContentTypeOptions]
    StrictTransportSecurity: Optional[ResponseHeadersPolicyStrictTransportSecurity]


class ResponseHeadersPolicyAccessControlExposeHeaders(TypedDict, total=False):
    Quantity: integer
    Items: Optional[AccessControlExposeHeadersList]


class ResponseHeadersPolicyAccessControlAllowMethods(TypedDict, total=False):
    Quantity: integer
    Items: AccessControlAllowMethodsList


class ResponseHeadersPolicyAccessControlAllowHeaders(TypedDict, total=False):
    Quantity: integer
    Items: AccessControlAllowHeadersList


class ResponseHeadersPolicyAccessControlAllowOrigins(TypedDict, total=False):
    Quantity: integer
    Items: AccessControlAllowOriginsList


class ResponseHeadersPolicyCorsConfig(TypedDict, total=False):
    AccessControlAllowOrigins: ResponseHeadersPolicyAccessControlAllowOrigins
    AccessControlAllowHeaders: ResponseHeadersPolicyAccessControlAllowHeaders
    AccessControlAllowMethods: ResponseHeadersPolicyAccessControlAllowMethods
    AccessControlAllowCredentials: boolean
    AccessControlExposeHeaders: Optional[ResponseHeadersPolicyAccessControlExposeHeaders]
    AccessControlMaxAgeSec: Optional[integer]
    OriginOverride: boolean


class ResponseHeadersPolicyConfig(TypedDict, total=False):
    Comment: Optional[string]
    Name: string
    CorsConfig: Optional[ResponseHeadersPolicyCorsConfig]
    SecurityHeadersConfig: Optional[ResponseHeadersPolicySecurityHeadersConfig]
    CustomHeadersConfig: Optional[ResponseHeadersPolicyCustomHeadersConfig]


class CreateResponseHeadersPolicyRequest(ServiceRequest):
    ResponseHeadersPolicyConfig: ResponseHeadersPolicyConfig


class ResponseHeadersPolicy(TypedDict, total=False):
    Id: string
    LastModifiedTime: timestamp
    ResponseHeadersPolicyConfig: ResponseHeadersPolicyConfig


class CreateResponseHeadersPolicyResult(TypedDict, total=False):
    ResponseHeadersPolicy: Optional[ResponseHeadersPolicy]
    Location: Optional[string]
    ETag: Optional[string]


class StreamingLoggingConfig(TypedDict, total=False):
    Enabled: boolean
    Bucket: string
    Prefix: string


class S3Origin(TypedDict, total=False):
    DomainName: string
    OriginAccessIdentity: string


class StreamingDistributionConfig(TypedDict, total=False):
    CallerReference: string
    S3Origin: S3Origin
    Aliases: Optional[Aliases]
    Comment: string
    Logging: Optional[StreamingLoggingConfig]
    TrustedSigners: TrustedSigners
    PriceClass: Optional[PriceClass]
    Enabled: boolean


class CreateStreamingDistributionRequest(ServiceRequest):
    StreamingDistributionConfig: StreamingDistributionConfig


class StreamingDistribution(TypedDict, total=False):
    Id: string
    ARN: string
    Status: string
    LastModifiedTime: Optional[timestamp]
    DomainName: string
    ActiveTrustedSigners: ActiveTrustedSigners
    StreamingDistributionConfig: StreamingDistributionConfig


class CreateStreamingDistributionResult(TypedDict, total=False):
    StreamingDistribution: Optional[StreamingDistribution]
    Location: Optional[string]
    ETag: Optional[string]


class StreamingDistributionConfigWithTags(TypedDict, total=False):
    StreamingDistributionConfig: StreamingDistributionConfig
    Tags: Tags


class CreateStreamingDistributionWithTagsRequest(ServiceRequest):
    StreamingDistributionConfigWithTags: StreamingDistributionConfigWithTags


class CreateStreamingDistributionWithTagsResult(TypedDict, total=False):
    StreamingDistribution: Optional[StreamingDistribution]
    Location: Optional[string]
    ETag: Optional[string]


class DeleteCachePolicyRequest(ServiceRequest):
    Id: string
    IfMatch: Optional[string]


class DeleteCloudFrontOriginAccessIdentityRequest(ServiceRequest):
    Id: string
    IfMatch: Optional[string]


class DeleteDistributionRequest(ServiceRequest):
    Id: string
    IfMatch: Optional[string]


class DeleteFieldLevelEncryptionConfigRequest(ServiceRequest):
    Id: string
    IfMatch: Optional[string]


class DeleteFieldLevelEncryptionProfileRequest(ServiceRequest):
    Id: string
    IfMatch: Optional[string]


class DeleteFunctionRequest(ServiceRequest):
    Name: string
    IfMatch: string


class DeleteKeyGroupRequest(ServiceRequest):
    Id: string
    IfMatch: Optional[string]


class DeleteMonitoringSubscriptionRequest(ServiceRequest):
    DistributionId: string


class DeleteMonitoringSubscriptionResult(TypedDict, total=False):
    pass


class DeleteOriginRequestPolicyRequest(ServiceRequest):
    Id: string
    IfMatch: Optional[string]


class DeletePublicKeyRequest(ServiceRequest):
    Id: string
    IfMatch: Optional[string]


class DeleteRealtimeLogConfigRequest(ServiceRequest):
    Name: Optional[string]
    ARN: Optional[string]


class DeleteResponseHeadersPolicyRequest(ServiceRequest):
    Id: string
    IfMatch: Optional[string]


class DeleteStreamingDistributionRequest(ServiceRequest):
    Id: string
    IfMatch: Optional[string]


class DescribeFunctionRequest(ServiceRequest):
    Name: string
    Stage: Optional[FunctionStage]


class DescribeFunctionResult(TypedDict, total=False):
    FunctionSummary: Optional[FunctionSummary]
    ETag: Optional[string]


DistributionIdListSummary = List[string]


class DistributionIdList(TypedDict, total=False):
    Marker: string
    NextMarker: Optional[string]
    MaxItems: integer
    IsTruncated: boolean
    Quantity: integer
    Items: Optional[DistributionIdListSummary]


class DistributionSummary(TypedDict, total=False):
    Id: string
    ARN: string
    Status: string
    LastModifiedTime: timestamp
    DomainName: string
    Aliases: Aliases
    Origins: Origins
    OriginGroups: Optional[OriginGroups]
    DefaultCacheBehavior: DefaultCacheBehavior
    CacheBehaviors: CacheBehaviors
    CustomErrorResponses: CustomErrorResponses
    Comment: string
    PriceClass: PriceClass
    Enabled: boolean
    ViewerCertificate: ViewerCertificate
    Restrictions: Restrictions
    WebACLId: string
    HttpVersion: HttpVersion
    IsIPV6Enabled: boolean
    AliasICPRecordals: Optional[AliasICPRecordals]


DistributionSummaryList = List[DistributionSummary]


class DistributionList(TypedDict, total=False):
    Marker: string
    NextMarker: Optional[string]
    MaxItems: integer
    IsTruncated: boolean
    Quantity: integer
    Items: Optional[DistributionSummaryList]


class FieldLevelEncryptionSummary(TypedDict, total=False):
    Id: string
    LastModifiedTime: timestamp
    Comment: Optional[string]
    QueryArgProfileConfig: Optional[QueryArgProfileConfig]
    ContentTypeProfileConfig: Optional[ContentTypeProfileConfig]


FieldLevelEncryptionSummaryList = List[FieldLevelEncryptionSummary]


class FieldLevelEncryptionList(TypedDict, total=False):
    NextMarker: Optional[string]
    MaxItems: integer
    Quantity: integer
    Items: Optional[FieldLevelEncryptionSummaryList]


class FieldLevelEncryptionProfileSummary(TypedDict, total=False):
    Id: string
    LastModifiedTime: timestamp
    Name: string
    EncryptionEntities: EncryptionEntities
    Comment: Optional[string]


FieldLevelEncryptionProfileSummaryList = List[FieldLevelEncryptionProfileSummary]


class FieldLevelEncryptionProfileList(TypedDict, total=False):
    NextMarker: Optional[string]
    MaxItems: integer
    Quantity: integer
    Items: Optional[FieldLevelEncryptionProfileSummaryList]


FunctionEventObject = bytes
FunctionExecutionLogList = List[string]
FunctionSummaryList = List[FunctionSummary]


class FunctionList(TypedDict, total=False):
    NextMarker: Optional[string]
    MaxItems: integer
    Quantity: integer
    Items: Optional[FunctionSummaryList]


class GetCachePolicyConfigRequest(ServiceRequest):
    Id: string


class GetCachePolicyConfigResult(TypedDict, total=False):
    CachePolicyConfig: Optional[CachePolicyConfig]
    ETag: Optional[string]


class GetCachePolicyRequest(ServiceRequest):
    Id: string


class GetCachePolicyResult(TypedDict, total=False):
    CachePolicy: Optional[CachePolicy]
    ETag: Optional[string]


class GetCloudFrontOriginAccessIdentityConfigRequest(ServiceRequest):
    Id: string


class GetCloudFrontOriginAccessIdentityConfigResult(TypedDict, total=False):
    CloudFrontOriginAccessIdentityConfig: Optional[CloudFrontOriginAccessIdentityConfig]
    ETag: Optional[string]


class GetCloudFrontOriginAccessIdentityRequest(ServiceRequest):
    Id: string


class GetCloudFrontOriginAccessIdentityResult(TypedDict, total=False):
    CloudFrontOriginAccessIdentity: Optional[CloudFrontOriginAccessIdentity]
    ETag: Optional[string]


class GetDistributionConfigRequest(ServiceRequest):
    Id: string


class GetDistributionConfigResult(TypedDict, total=False):
    DistributionConfig: Optional[DistributionConfig]
    ETag: Optional[string]


class GetDistributionRequest(ServiceRequest):
    Id: string


class GetDistributionResult(TypedDict, total=False):
    Distribution: Optional[Distribution]
    ETag: Optional[string]


class GetFieldLevelEncryptionConfigRequest(ServiceRequest):
    Id: string


class GetFieldLevelEncryptionConfigResult(TypedDict, total=False):
    FieldLevelEncryptionConfig: Optional[FieldLevelEncryptionConfig]
    ETag: Optional[string]


class GetFieldLevelEncryptionProfileConfigRequest(ServiceRequest):
    Id: string


class GetFieldLevelEncryptionProfileConfigResult(TypedDict, total=False):
    FieldLevelEncryptionProfileConfig: Optional[FieldLevelEncryptionProfileConfig]
    ETag: Optional[string]


class GetFieldLevelEncryptionProfileRequest(ServiceRequest):
    Id: string


class GetFieldLevelEncryptionProfileResult(TypedDict, total=False):
    FieldLevelEncryptionProfile: Optional[FieldLevelEncryptionProfile]
    ETag: Optional[string]


class GetFieldLevelEncryptionRequest(ServiceRequest):
    Id: string


class GetFieldLevelEncryptionResult(TypedDict, total=False):
    FieldLevelEncryption: Optional[FieldLevelEncryption]
    ETag: Optional[string]


class GetFunctionRequest(ServiceRequest):
    Name: string
    Stage: Optional[FunctionStage]


class GetFunctionResult(TypedDict, total=False):
    FunctionCode: Optional[FunctionBlob]
    ETag: Optional[string]
    ContentType: Optional[string]


class GetInvalidationRequest(ServiceRequest):
    DistributionId: string
    Id: string


class GetInvalidationResult(TypedDict, total=False):
    Invalidation: Optional[Invalidation]


class GetKeyGroupConfigRequest(ServiceRequest):
    Id: string


class GetKeyGroupConfigResult(TypedDict, total=False):
    KeyGroupConfig: Optional[KeyGroupConfig]
    ETag: Optional[string]


class GetKeyGroupRequest(ServiceRequest):
    Id: string


class GetKeyGroupResult(TypedDict, total=False):
    KeyGroup: Optional[KeyGroup]
    ETag: Optional[string]


class GetMonitoringSubscriptionRequest(ServiceRequest):
    DistributionId: string


class GetMonitoringSubscriptionResult(TypedDict, total=False):
    MonitoringSubscription: Optional[MonitoringSubscription]


class GetOriginRequestPolicyConfigRequest(ServiceRequest):
    Id: string


class GetOriginRequestPolicyConfigResult(TypedDict, total=False):
    OriginRequestPolicyConfig: Optional[OriginRequestPolicyConfig]
    ETag: Optional[string]


class GetOriginRequestPolicyRequest(ServiceRequest):
    Id: string


class GetOriginRequestPolicyResult(TypedDict, total=False):
    OriginRequestPolicy: Optional[OriginRequestPolicy]
    ETag: Optional[string]


class GetPublicKeyConfigRequest(ServiceRequest):
    Id: string


class GetPublicKeyConfigResult(TypedDict, total=False):
    PublicKeyConfig: Optional[PublicKeyConfig]
    ETag: Optional[string]


class GetPublicKeyRequest(ServiceRequest):
    Id: string


class GetPublicKeyResult(TypedDict, total=False):
    PublicKey: Optional[PublicKey]
    ETag: Optional[string]


class GetRealtimeLogConfigRequest(ServiceRequest):
    Name: Optional[string]
    ARN: Optional[string]


class GetRealtimeLogConfigResult(TypedDict, total=False):
    RealtimeLogConfig: Optional[RealtimeLogConfig]


class GetResponseHeadersPolicyConfigRequest(ServiceRequest):
    Id: string


class GetResponseHeadersPolicyConfigResult(TypedDict, total=False):
    ResponseHeadersPolicyConfig: Optional[ResponseHeadersPolicyConfig]
    ETag: Optional[string]


class GetResponseHeadersPolicyRequest(ServiceRequest):
    Id: string


class GetResponseHeadersPolicyResult(TypedDict, total=False):
    ResponseHeadersPolicy: Optional[ResponseHeadersPolicy]
    ETag: Optional[string]


class GetStreamingDistributionConfigRequest(ServiceRequest):
    Id: string


class GetStreamingDistributionConfigResult(TypedDict, total=False):
    StreamingDistributionConfig: Optional[StreamingDistributionConfig]
    ETag: Optional[string]


class GetStreamingDistributionRequest(ServiceRequest):
    Id: string


class GetStreamingDistributionResult(TypedDict, total=False):
    StreamingDistribution: Optional[StreamingDistribution]
    ETag: Optional[string]


class InvalidationSummary(TypedDict, total=False):
    Id: string
    CreateTime: timestamp
    Status: string


InvalidationSummaryList = List[InvalidationSummary]


class InvalidationList(TypedDict, total=False):
    Marker: string
    NextMarker: Optional[string]
    MaxItems: integer
    IsTruncated: boolean
    Quantity: integer
    Items: Optional[InvalidationSummaryList]


class KeyGroupSummary(TypedDict, total=False):
    KeyGroup: KeyGroup


KeyGroupSummaryList = List[KeyGroupSummary]


class KeyGroupList(TypedDict, total=False):
    NextMarker: Optional[string]
    MaxItems: integer
    Quantity: integer
    Items: Optional[KeyGroupSummaryList]


class ListCachePoliciesRequest(ServiceRequest):
    Type: Optional[CachePolicyType]
    Marker: Optional[string]
    MaxItems: Optional[string]


class ListCachePoliciesResult(TypedDict, total=False):
    CachePolicyList: Optional[CachePolicyList]


class ListCloudFrontOriginAccessIdentitiesRequest(ServiceRequest):
    Marker: Optional[string]
    MaxItems: Optional[string]


class ListCloudFrontOriginAccessIdentitiesResult(TypedDict, total=False):
    CloudFrontOriginAccessIdentityList: Optional[CloudFrontOriginAccessIdentityList]


class ListConflictingAliasesRequest(ServiceRequest):
    DistributionId: distributionIdString
    Alias: aliasString
    Marker: Optional[string]
    MaxItems: Optional[listConflictingAliasesMaxItemsInteger]


class ListConflictingAliasesResult(TypedDict, total=False):
    ConflictingAliasesList: Optional[ConflictingAliasesList]


class ListDistributionsByCachePolicyIdRequest(ServiceRequest):
    Marker: Optional[string]
    MaxItems: Optional[string]
    CachePolicyId: string


class ListDistributionsByCachePolicyIdResult(TypedDict, total=False):
    DistributionIdList: Optional[DistributionIdList]


class ListDistributionsByKeyGroupRequest(ServiceRequest):
    Marker: Optional[string]
    MaxItems: Optional[string]
    KeyGroupId: string


class ListDistributionsByKeyGroupResult(TypedDict, total=False):
    DistributionIdList: Optional[DistributionIdList]


class ListDistributionsByOriginRequestPolicyIdRequest(ServiceRequest):
    Marker: Optional[string]
    MaxItems: Optional[string]
    OriginRequestPolicyId: string


class ListDistributionsByOriginRequestPolicyIdResult(TypedDict, total=False):
    DistributionIdList: Optional[DistributionIdList]


class ListDistributionsByRealtimeLogConfigRequest(ServiceRequest):
    Marker: Optional[string]
    MaxItems: Optional[string]
    RealtimeLogConfigName: Optional[string]
    RealtimeLogConfigArn: Optional[string]


class ListDistributionsByRealtimeLogConfigResult(TypedDict, total=False):
    DistributionList: Optional[DistributionList]


class ListDistributionsByResponseHeadersPolicyIdRequest(ServiceRequest):
    Marker: Optional[string]
    MaxItems: Optional[string]
    ResponseHeadersPolicyId: string


class ListDistributionsByResponseHeadersPolicyIdResult(TypedDict, total=False):
    DistributionIdList: Optional[DistributionIdList]


class ListDistributionsByWebACLIdRequest(ServiceRequest):
    Marker: Optional[string]
    MaxItems: Optional[string]
    WebACLId: string


class ListDistributionsByWebACLIdResult(TypedDict, total=False):
    DistributionList: Optional[DistributionList]


class ListDistributionsRequest(ServiceRequest):
    Marker: Optional[string]
    MaxItems: Optional[string]


class ListDistributionsResult(TypedDict, total=False):
    DistributionList: Optional[DistributionList]


class ListFieldLevelEncryptionConfigsRequest(ServiceRequest):
    Marker: Optional[string]
    MaxItems: Optional[string]


class ListFieldLevelEncryptionConfigsResult(TypedDict, total=False):
    FieldLevelEncryptionList: Optional[FieldLevelEncryptionList]


class ListFieldLevelEncryptionProfilesRequest(ServiceRequest):
    Marker: Optional[string]
    MaxItems: Optional[string]


class ListFieldLevelEncryptionProfilesResult(TypedDict, total=False):
    FieldLevelEncryptionProfileList: Optional[FieldLevelEncryptionProfileList]


class ListFunctionsRequest(ServiceRequest):
    Marker: Optional[string]
    MaxItems: Optional[string]
    Stage: Optional[FunctionStage]


class ListFunctionsResult(TypedDict, total=False):
    FunctionList: Optional[FunctionList]


class ListInvalidationsRequest(ServiceRequest):
    DistributionId: string
    Marker: Optional[string]
    MaxItems: Optional[string]


class ListInvalidationsResult(TypedDict, total=False):
    InvalidationList: Optional[InvalidationList]


class ListKeyGroupsRequest(ServiceRequest):
    Marker: Optional[string]
    MaxItems: Optional[string]


class ListKeyGroupsResult(TypedDict, total=False):
    KeyGroupList: Optional[KeyGroupList]


class ListOriginRequestPoliciesRequest(ServiceRequest):
    Type: Optional[OriginRequestPolicyType]
    Marker: Optional[string]
    MaxItems: Optional[string]


class OriginRequestPolicySummary(TypedDict, total=False):
    Type: OriginRequestPolicyType
    OriginRequestPolicy: OriginRequestPolicy


OriginRequestPolicySummaryList = List[OriginRequestPolicySummary]


class OriginRequestPolicyList(TypedDict, total=False):
    NextMarker: Optional[string]
    MaxItems: integer
    Quantity: integer
    Items: Optional[OriginRequestPolicySummaryList]


class ListOriginRequestPoliciesResult(TypedDict, total=False):
    OriginRequestPolicyList: Optional[OriginRequestPolicyList]


class ListPublicKeysRequest(ServiceRequest):
    Marker: Optional[string]
    MaxItems: Optional[string]


class PublicKeySummary(TypedDict, total=False):
    Id: string
    Name: string
    CreatedTime: timestamp
    EncodedKey: string
    Comment: Optional[string]


PublicKeySummaryList = List[PublicKeySummary]


class PublicKeyList(TypedDict, total=False):
    NextMarker: Optional[string]
    MaxItems: integer
    Quantity: integer
    Items: Optional[PublicKeySummaryList]


class ListPublicKeysResult(TypedDict, total=False):
    PublicKeyList: Optional[PublicKeyList]


class ListRealtimeLogConfigsRequest(ServiceRequest):
    MaxItems: Optional[string]
    Marker: Optional[string]


RealtimeLogConfigList = List[RealtimeLogConfig]


class RealtimeLogConfigs(TypedDict, total=False):
    MaxItems: integer
    Items: Optional[RealtimeLogConfigList]
    IsTruncated: boolean
    Marker: string
    NextMarker: Optional[string]


class ListRealtimeLogConfigsResult(TypedDict, total=False):
    RealtimeLogConfigs: Optional[RealtimeLogConfigs]


class ListResponseHeadersPoliciesRequest(ServiceRequest):
    Type: Optional[ResponseHeadersPolicyType]
    Marker: Optional[string]
    MaxItems: Optional[string]


class ResponseHeadersPolicySummary(TypedDict, total=False):
    Type: ResponseHeadersPolicyType
    ResponseHeadersPolicy: ResponseHeadersPolicy


ResponseHeadersPolicySummaryList = List[ResponseHeadersPolicySummary]


class ResponseHeadersPolicyList(TypedDict, total=False):
    NextMarker: Optional[string]
    MaxItems: integer
    Quantity: integer
    Items: Optional[ResponseHeadersPolicySummaryList]


class ListResponseHeadersPoliciesResult(TypedDict, total=False):
    ResponseHeadersPolicyList: Optional[ResponseHeadersPolicyList]


class ListStreamingDistributionsRequest(ServiceRequest):
    Marker: Optional[string]
    MaxItems: Optional[string]


class StreamingDistributionSummary(TypedDict, total=False):
    Id: string
    ARN: string
    Status: string
    LastModifiedTime: timestamp
    DomainName: string
    S3Origin: S3Origin
    Aliases: Aliases
    TrustedSigners: TrustedSigners
    Comment: string
    PriceClass: PriceClass
    Enabled: boolean


StreamingDistributionSummaryList = List[StreamingDistributionSummary]


class StreamingDistributionList(TypedDict, total=False):
    Marker: string
    NextMarker: Optional[string]
    MaxItems: integer
    IsTruncated: boolean
    Quantity: integer
    Items: Optional[StreamingDistributionSummaryList]


class ListStreamingDistributionsResult(TypedDict, total=False):
    StreamingDistributionList: Optional[StreamingDistributionList]


class ListTagsForResourceRequest(ServiceRequest):
    Resource: ResourceARN


class ListTagsForResourceResult(TypedDict, total=False):
    Tags: Tags


class PublishFunctionRequest(ServiceRequest):
    Name: string
    IfMatch: string


class PublishFunctionResult(TypedDict, total=False):
    FunctionSummary: Optional[FunctionSummary]


TagKeyList = List[TagKey]


class TagKeys(TypedDict, total=False):
    Items: Optional[TagKeyList]


class TagResourceRequest(ServiceRequest):
    Resource: ResourceARN
    Tags: Tags


class TestFunctionRequest(ServiceRequest):
    Name: string
    IfMatch: string
    Stage: Optional[FunctionStage]
    EventObject: FunctionEventObject


class TestResult(TypedDict, total=False):
    FunctionSummary: Optional[FunctionSummary]
    ComputeUtilization: Optional[string]
    FunctionExecutionLogs: Optional[FunctionExecutionLogList]
    FunctionErrorMessage: Optional[sensitiveStringType]
    FunctionOutput: Optional[sensitiveStringType]


class TestFunctionResult(TypedDict, total=False):
    TestResult: Optional[TestResult]


class UntagResourceRequest(ServiceRequest):
    Resource: ResourceARN
    TagKeys: TagKeys


class UpdateCachePolicyRequest(ServiceRequest):
    CachePolicyConfig: CachePolicyConfig
    Id: string
    IfMatch: Optional[string]


class UpdateCachePolicyResult(TypedDict, total=False):
    CachePolicy: Optional[CachePolicy]
    ETag: Optional[string]


class UpdateCloudFrontOriginAccessIdentityRequest(ServiceRequest):
    CloudFrontOriginAccessIdentityConfig: CloudFrontOriginAccessIdentityConfig
    Id: string
    IfMatch: Optional[string]


class UpdateCloudFrontOriginAccessIdentityResult(TypedDict, total=False):
    CloudFrontOriginAccessIdentity: Optional[CloudFrontOriginAccessIdentity]
    ETag: Optional[string]


class UpdateDistributionRequest(ServiceRequest):
    DistributionConfig: DistributionConfig
    Id: string
    IfMatch: Optional[string]


class UpdateDistributionResult(TypedDict, total=False):
    Distribution: Optional[Distribution]
    ETag: Optional[string]


class UpdateFieldLevelEncryptionConfigRequest(ServiceRequest):
    FieldLevelEncryptionConfig: FieldLevelEncryptionConfig
    Id: string
    IfMatch: Optional[string]


class UpdateFieldLevelEncryptionConfigResult(TypedDict, total=False):
    FieldLevelEncryption: Optional[FieldLevelEncryption]
    ETag: Optional[string]


class UpdateFieldLevelEncryptionProfileRequest(ServiceRequest):
    FieldLevelEncryptionProfileConfig: FieldLevelEncryptionProfileConfig
    Id: string
    IfMatch: Optional[string]


class UpdateFieldLevelEncryptionProfileResult(TypedDict, total=False):
    FieldLevelEncryptionProfile: Optional[FieldLevelEncryptionProfile]
    ETag: Optional[string]


class UpdateFunctionRequest(ServiceRequest):
    Name: string
    IfMatch: string
    FunctionConfig: FunctionConfig
    FunctionCode: FunctionBlob


class UpdateFunctionResult(TypedDict, total=False):
    FunctionSummary: Optional[FunctionSummary]
    ETag: Optional[string]


class UpdateKeyGroupRequest(ServiceRequest):
    KeyGroupConfig: KeyGroupConfig
    Id: string
    IfMatch: Optional[string]


class UpdateKeyGroupResult(TypedDict, total=False):
    KeyGroup: Optional[KeyGroup]
    ETag: Optional[string]


class UpdateOriginRequestPolicyRequest(ServiceRequest):
    OriginRequestPolicyConfig: OriginRequestPolicyConfig
    Id: string
    IfMatch: Optional[string]


class UpdateOriginRequestPolicyResult(TypedDict, total=False):
    OriginRequestPolicy: Optional[OriginRequestPolicy]
    ETag: Optional[string]


class UpdatePublicKeyRequest(ServiceRequest):
    PublicKeyConfig: PublicKeyConfig
    Id: string
    IfMatch: Optional[string]


class UpdatePublicKeyResult(TypedDict, total=False):
    PublicKey: Optional[PublicKey]
    ETag: Optional[string]


class UpdateRealtimeLogConfigRequest(ServiceRequest):
    EndPoints: Optional[EndPointList]
    Fields: Optional[FieldList]
    Name: Optional[string]
    ARN: Optional[string]
    SamplingRate: Optional[long]


class UpdateRealtimeLogConfigResult(TypedDict, total=False):
    RealtimeLogConfig: Optional[RealtimeLogConfig]


class UpdateResponseHeadersPolicyRequest(ServiceRequest):
    ResponseHeadersPolicyConfig: ResponseHeadersPolicyConfig
    Id: string
    IfMatch: Optional[string]


class UpdateResponseHeadersPolicyResult(TypedDict, total=False):
    ResponseHeadersPolicy: Optional[ResponseHeadersPolicy]
    ETag: Optional[string]


class UpdateStreamingDistributionRequest(ServiceRequest):
    StreamingDistributionConfig: StreamingDistributionConfig
    Id: string
    IfMatch: Optional[string]


class UpdateStreamingDistributionResult(TypedDict, total=False):
    StreamingDistribution: Optional[StreamingDistribution]
    ETag: Optional[string]


class CloudfrontApi:

    service = "cloudfront"
    version = "2020-05-31"

    @handler("AssociateAlias")
    def associate_alias(
        self, context: RequestContext, target_distribution_id: string, alias: string
    ) -> None:
        raise NotImplementedError

    @handler("CreateCachePolicy")
    def create_cache_policy(
        self, context: RequestContext, cache_policy_config: CachePolicyConfig
    ) -> CreateCachePolicyResult:
        raise NotImplementedError

    @handler("CreateCloudFrontOriginAccessIdentity")
    def create_cloud_front_origin_access_identity(
        self,
        context: RequestContext,
        cloud_front_origin_access_identity_config: CloudFrontOriginAccessIdentityConfig,
    ) -> CreateCloudFrontOriginAccessIdentityResult:
        raise NotImplementedError

    @handler("CreateDistribution")
    def create_distribution(
        self, context: RequestContext, distribution_config: DistributionConfig
    ) -> CreateDistributionResult:
        raise NotImplementedError

    @handler("CreateDistributionWithTags")
    def create_distribution_with_tags(
        self, context: RequestContext, distribution_config_with_tags: DistributionConfigWithTags
    ) -> CreateDistributionWithTagsResult:
        raise NotImplementedError

    @handler("CreateFieldLevelEncryptionConfig")
    def create_field_level_encryption_config(
        self, context: RequestContext, field_level_encryption_config: FieldLevelEncryptionConfig
    ) -> CreateFieldLevelEncryptionConfigResult:
        raise NotImplementedError

    @handler("CreateFieldLevelEncryptionProfile")
    def create_field_level_encryption_profile(
        self,
        context: RequestContext,
        field_level_encryption_profile_config: FieldLevelEncryptionProfileConfig,
    ) -> CreateFieldLevelEncryptionProfileResult:
        raise NotImplementedError

    @handler("CreateFunction")
    def create_function(
        self,
        context: RequestContext,
        name: FunctionName,
        function_config: FunctionConfig,
        function_code: FunctionBlob,
    ) -> CreateFunctionResult:
        raise NotImplementedError

    @handler("CreateInvalidation")
    def create_invalidation(
        self,
        context: RequestContext,
        distribution_id: string,
        invalidation_batch: InvalidationBatch,
    ) -> CreateInvalidationResult:
        raise NotImplementedError

    @handler("CreateKeyGroup")
    def create_key_group(
        self, context: RequestContext, key_group_config: KeyGroupConfig
    ) -> CreateKeyGroupResult:
        raise NotImplementedError

    @handler("CreateMonitoringSubscription")
    def create_monitoring_subscription(
        self,
        context: RequestContext,
        monitoring_subscription: MonitoringSubscription,
        distribution_id: string,
    ) -> CreateMonitoringSubscriptionResult:
        raise NotImplementedError

    @handler("CreateOriginRequestPolicy")
    def create_origin_request_policy(
        self, context: RequestContext, origin_request_policy_config: OriginRequestPolicyConfig
    ) -> CreateOriginRequestPolicyResult:
        raise NotImplementedError

    @handler("CreatePublicKey")
    def create_public_key(
        self, context: RequestContext, public_key_config: PublicKeyConfig
    ) -> CreatePublicKeyResult:
        raise NotImplementedError

    @handler("CreateRealtimeLogConfig")
    def create_realtime_log_config(
        self,
        context: RequestContext,
        end_points: EndPointList,
        fields: FieldList,
        name: string,
        sampling_rate: long,
    ) -> CreateRealtimeLogConfigResult:
        raise NotImplementedError

    @handler("CreateResponseHeadersPolicy")
    def create_response_headers_policy(
        self, context: RequestContext, response_headers_policy_config: ResponseHeadersPolicyConfig
    ) -> CreateResponseHeadersPolicyResult:
        raise NotImplementedError

    @handler("CreateStreamingDistribution")
    def create_streaming_distribution(
        self, context: RequestContext, streaming_distribution_config: StreamingDistributionConfig
    ) -> CreateStreamingDistributionResult:
        raise NotImplementedError

    @handler("CreateStreamingDistributionWithTags")
    def create_streaming_distribution_with_tags(
        self,
        context: RequestContext,
        streaming_distribution_config_with_tags: StreamingDistributionConfigWithTags,
    ) -> CreateStreamingDistributionWithTagsResult:
        raise NotImplementedError

    @handler("DeleteCachePolicy")
    def delete_cache_policy(
        self, context: RequestContext, id: string, if_match: string = None
    ) -> None:
        raise NotImplementedError

    @handler("DeleteCloudFrontOriginAccessIdentity")
    def delete_cloud_front_origin_access_identity(
        self, context: RequestContext, id: string, if_match: string = None
    ) -> None:
        raise NotImplementedError

    @handler("DeleteDistribution")
    def delete_distribution(
        self, context: RequestContext, id: string, if_match: string = None
    ) -> None:
        raise NotImplementedError

    @handler("DeleteFieldLevelEncryptionConfig")
    def delete_field_level_encryption_config(
        self, context: RequestContext, id: string, if_match: string = None
    ) -> None:
        raise NotImplementedError

    @handler("DeleteFieldLevelEncryptionProfile")
    def delete_field_level_encryption_profile(
        self, context: RequestContext, id: string, if_match: string = None
    ) -> None:
        raise NotImplementedError

    @handler("DeleteFunction")
    def delete_function(self, context: RequestContext, if_match: string, name: string) -> None:
        raise NotImplementedError

    @handler("DeleteKeyGroup")
    def delete_key_group(
        self, context: RequestContext, id: string, if_match: string = None
    ) -> None:
        raise NotImplementedError

    @handler("DeleteMonitoringSubscription")
    def delete_monitoring_subscription(
        self, context: RequestContext, distribution_id: string
    ) -> DeleteMonitoringSubscriptionResult:
        raise NotImplementedError

    @handler("DeleteOriginRequestPolicy")
    def delete_origin_request_policy(
        self, context: RequestContext, id: string, if_match: string = None
    ) -> None:
        raise NotImplementedError

    @handler("DeletePublicKey")
    def delete_public_key(
        self, context: RequestContext, id: string, if_match: string = None
    ) -> None:
        raise NotImplementedError

    @handler("DeleteRealtimeLogConfig")
    def delete_realtime_log_config(
        self, context: RequestContext, name: string = None, arn: string = None
    ) -> None:
        raise NotImplementedError

    @handler("DeleteResponseHeadersPolicy")
    def delete_response_headers_policy(
        self, context: RequestContext, id: string, if_match: string = None
    ) -> None:
        raise NotImplementedError

    @handler("DeleteStreamingDistribution")
    def delete_streaming_distribution(
        self, context: RequestContext, id: string, if_match: string = None
    ) -> None:
        raise NotImplementedError

    @handler("DescribeFunction")
    def describe_function(
        self, context: RequestContext, name: string, stage: FunctionStage = None
    ) -> DescribeFunctionResult:
        raise NotImplementedError

    @handler("GetCachePolicy")
    def get_cache_policy(self, context: RequestContext, id: string) -> GetCachePolicyResult:
        raise NotImplementedError

    @handler("GetCachePolicyConfig")
    def get_cache_policy_config(
        self, context: RequestContext, id: string
    ) -> GetCachePolicyConfigResult:
        raise NotImplementedError

    @handler("GetCloudFrontOriginAccessIdentity")
    def get_cloud_front_origin_access_identity(
        self, context: RequestContext, id: string
    ) -> GetCloudFrontOriginAccessIdentityResult:
        raise NotImplementedError

    @handler("GetCloudFrontOriginAccessIdentityConfig")
    def get_cloud_front_origin_access_identity_config(
        self, context: RequestContext, id: string
    ) -> GetCloudFrontOriginAccessIdentityConfigResult:
        raise NotImplementedError

    @handler("GetDistribution")
    def get_distribution(self, context: RequestContext, id: string) -> GetDistributionResult:
        raise NotImplementedError

    @handler("GetDistributionConfig")
    def get_distribution_config(
        self, context: RequestContext, id: string
    ) -> GetDistributionConfigResult:
        raise NotImplementedError

    @handler("GetFieldLevelEncryption")
    def get_field_level_encryption(
        self, context: RequestContext, id: string
    ) -> GetFieldLevelEncryptionResult:
        raise NotImplementedError

    @handler("GetFieldLevelEncryptionConfig")
    def get_field_level_encryption_config(
        self, context: RequestContext, id: string
    ) -> GetFieldLevelEncryptionConfigResult:
        raise NotImplementedError

    @handler("GetFieldLevelEncryptionProfile")
    def get_field_level_encryption_profile(
        self, context: RequestContext, id: string
    ) -> GetFieldLevelEncryptionProfileResult:
        raise NotImplementedError

    @handler("GetFieldLevelEncryptionProfileConfig")
    def get_field_level_encryption_profile_config(
        self, context: RequestContext, id: string
    ) -> GetFieldLevelEncryptionProfileConfigResult:
        raise NotImplementedError

    @handler("GetFunction")
    def get_function(
        self, context: RequestContext, name: string, stage: FunctionStage = None
    ) -> GetFunctionResult:
        raise NotImplementedError

    @handler("GetInvalidation")
    def get_invalidation(
        self, context: RequestContext, distribution_id: string, id: string
    ) -> GetInvalidationResult:
        raise NotImplementedError

    @handler("GetKeyGroup")
    def get_key_group(self, context: RequestContext, id: string) -> GetKeyGroupResult:
        raise NotImplementedError

    @handler("GetKeyGroupConfig")
    def get_key_group_config(self, context: RequestContext, id: string) -> GetKeyGroupConfigResult:
        raise NotImplementedError

    @handler("GetMonitoringSubscription")
    def get_monitoring_subscription(
        self, context: RequestContext, distribution_id: string
    ) -> GetMonitoringSubscriptionResult:
        raise NotImplementedError

    @handler("GetOriginRequestPolicy")
    def get_origin_request_policy(
        self, context: RequestContext, id: string
    ) -> GetOriginRequestPolicyResult:
        raise NotImplementedError

    @handler("GetOriginRequestPolicyConfig")
    def get_origin_request_policy_config(
        self, context: RequestContext, id: string
    ) -> GetOriginRequestPolicyConfigResult:
        raise NotImplementedError

    @handler("GetPublicKey")
    def get_public_key(self, context: RequestContext, id: string) -> GetPublicKeyResult:
        raise NotImplementedError

    @handler("GetPublicKeyConfig")
    def get_public_key_config(
        self, context: RequestContext, id: string
    ) -> GetPublicKeyConfigResult:
        raise NotImplementedError

    @handler("GetRealtimeLogConfig")
    def get_realtime_log_config(
        self, context: RequestContext, name: string = None, arn: string = None
    ) -> GetRealtimeLogConfigResult:
        raise NotImplementedError

    @handler("GetResponseHeadersPolicy")
    def get_response_headers_policy(
        self, context: RequestContext, id: string
    ) -> GetResponseHeadersPolicyResult:
        raise NotImplementedError

    @handler("GetResponseHeadersPolicyConfig")
    def get_response_headers_policy_config(
        self, context: RequestContext, id: string
    ) -> GetResponseHeadersPolicyConfigResult:
        raise NotImplementedError

    @handler("GetStreamingDistribution")
    def get_streaming_distribution(
        self, context: RequestContext, id: string
    ) -> GetStreamingDistributionResult:
        raise NotImplementedError

    @handler("GetStreamingDistributionConfig")
    def get_streaming_distribution_config(
        self, context: RequestContext, id: string
    ) -> GetStreamingDistributionConfigResult:
        raise NotImplementedError

    @handler("ListCachePolicies", expand=False)
    def list_cache_policies(
        self, context: RequestContext, request: ListCachePoliciesRequest
    ) -> ListCachePoliciesResult:
        raise NotImplementedError

    @handler("ListCloudFrontOriginAccessIdentities")
    def list_cloud_front_origin_access_identities(
        self, context: RequestContext, marker: string = None, max_items: string = None
    ) -> ListCloudFrontOriginAccessIdentitiesResult:
        raise NotImplementedError

    @handler("ListConflictingAliases")
    def list_conflicting_aliases(
        self,
        context: RequestContext,
        distribution_id: distributionIdString,
        alias: aliasString,
        marker: string = None,
        max_items: listConflictingAliasesMaxItemsInteger = None,
    ) -> ListConflictingAliasesResult:
        raise NotImplementedError

    @handler("ListDistributions")
    def list_distributions(
        self, context: RequestContext, marker: string = None, max_items: string = None
    ) -> ListDistributionsResult:
        raise NotImplementedError

    @handler("ListDistributionsByCachePolicyId")
    def list_distributions_by_cache_policy_id(
        self,
        context: RequestContext,
        cache_policy_id: string,
        marker: string = None,
        max_items: string = None,
    ) -> ListDistributionsByCachePolicyIdResult:
        raise NotImplementedError

    @handler("ListDistributionsByKeyGroup")
    def list_distributions_by_key_group(
        self,
        context: RequestContext,
        key_group_id: string,
        marker: string = None,
        max_items: string = None,
    ) -> ListDistributionsByKeyGroupResult:
        raise NotImplementedError

    @handler("ListDistributionsByOriginRequestPolicyId")
    def list_distributions_by_origin_request_policy_id(
        self,
        context: RequestContext,
        origin_request_policy_id: string,
        marker: string = None,
        max_items: string = None,
    ) -> ListDistributionsByOriginRequestPolicyIdResult:
        raise NotImplementedError

    @handler("ListDistributionsByRealtimeLogConfig")
    def list_distributions_by_realtime_log_config(
        self,
        context: RequestContext,
        marker: string = None,
        max_items: string = None,
        realtime_log_config_name: string = None,
        realtime_log_config_arn: string = None,
    ) -> ListDistributionsByRealtimeLogConfigResult:
        raise NotImplementedError

    @handler("ListDistributionsByResponseHeadersPolicyId")
    def list_distributions_by_response_headers_policy_id(
        self,
        context: RequestContext,
        response_headers_policy_id: string,
        marker: string = None,
        max_items: string = None,
    ) -> ListDistributionsByResponseHeadersPolicyIdResult:
        raise NotImplementedError

    @handler("ListDistributionsByWebACLId")
    def list_distributions_by_web_acl_id(
        self,
        context: RequestContext,
        web_acl_id: string,
        marker: string = None,
        max_items: string = None,
    ) -> ListDistributionsByWebACLIdResult:
        raise NotImplementedError

    @handler("ListFieldLevelEncryptionConfigs")
    def list_field_level_encryption_configs(
        self, context: RequestContext, marker: string = None, max_items: string = None
    ) -> ListFieldLevelEncryptionConfigsResult:
        raise NotImplementedError

    @handler("ListFieldLevelEncryptionProfiles")
    def list_field_level_encryption_profiles(
        self, context: RequestContext, marker: string = None, max_items: string = None
    ) -> ListFieldLevelEncryptionProfilesResult:
        raise NotImplementedError

    @handler("ListFunctions")
    def list_functions(
        self,
        context: RequestContext,
        marker: string = None,
        max_items: string = None,
        stage: FunctionStage = None,
    ) -> ListFunctionsResult:
        raise NotImplementedError

    @handler("ListInvalidations")
    def list_invalidations(
        self,
        context: RequestContext,
        distribution_id: string,
        marker: string = None,
        max_items: string = None,
    ) -> ListInvalidationsResult:
        raise NotImplementedError

    @handler("ListKeyGroups")
    def list_key_groups(
        self, context: RequestContext, marker: string = None, max_items: string = None
    ) -> ListKeyGroupsResult:
        raise NotImplementedError

    @handler("ListOriginRequestPolicies", expand=False)
    def list_origin_request_policies(
        self, context: RequestContext, request: ListOriginRequestPoliciesRequest
    ) -> ListOriginRequestPoliciesResult:
        raise NotImplementedError

    @handler("ListPublicKeys")
    def list_public_keys(
        self, context: RequestContext, marker: string = None, max_items: string = None
    ) -> ListPublicKeysResult:
        raise NotImplementedError

    @handler("ListRealtimeLogConfigs")
    def list_realtime_log_configs(
        self, context: RequestContext, max_items: string = None, marker: string = None
    ) -> ListRealtimeLogConfigsResult:
        raise NotImplementedError

    @handler("ListResponseHeadersPolicies", expand=False)
    def list_response_headers_policies(
        self, context: RequestContext, request: ListResponseHeadersPoliciesRequest
    ) -> ListResponseHeadersPoliciesResult:
        raise NotImplementedError

    @handler("ListStreamingDistributions")
    def list_streaming_distributions(
        self, context: RequestContext, marker: string = None, max_items: string = None
    ) -> ListStreamingDistributionsResult:
        raise NotImplementedError

    @handler("ListTagsForResource")
    def list_tags_for_resource(
        self, context: RequestContext, resource: ResourceARN
    ) -> ListTagsForResourceResult:
        raise NotImplementedError

    @handler("PublishFunction")
    def publish_function(
        self, context: RequestContext, name: string, if_match: string
    ) -> PublishFunctionResult:
        raise NotImplementedError

    @handler("TagResource")
    def tag_resource(self, context: RequestContext, resource: ResourceARN, tags: Tags) -> None:
        raise NotImplementedError

    @handler("TestFunction")
    def test_function(
        self,
        context: RequestContext,
        name: string,
        if_match: string,
        event_object: FunctionEventObject,
        stage: FunctionStage = None,
    ) -> TestFunctionResult:
        raise NotImplementedError

    @handler("UntagResource")
    def untag_resource(
        self, context: RequestContext, resource: ResourceARN, tag_keys: TagKeys
    ) -> None:
        raise NotImplementedError

    @handler("UpdateCachePolicy")
    def update_cache_policy(
        self,
        context: RequestContext,
        cache_policy_config: CachePolicyConfig,
        id: string,
        if_match: string = None,
    ) -> UpdateCachePolicyResult:
        raise NotImplementedError

    @handler("UpdateCloudFrontOriginAccessIdentity")
    def update_cloud_front_origin_access_identity(
        self,
        context: RequestContext,
        cloud_front_origin_access_identity_config: CloudFrontOriginAccessIdentityConfig,
        id: string,
        if_match: string = None,
    ) -> UpdateCloudFrontOriginAccessIdentityResult:
        raise NotImplementedError

    @handler("UpdateDistribution")
    def update_distribution(
        self,
        context: RequestContext,
        distribution_config: DistributionConfig,
        id: string,
        if_match: string = None,
    ) -> UpdateDistributionResult:
        raise NotImplementedError

    @handler("UpdateFieldLevelEncryptionConfig")
    def update_field_level_encryption_config(
        self,
        context: RequestContext,
        field_level_encryption_config: FieldLevelEncryptionConfig,
        id: string,
        if_match: string = None,
    ) -> UpdateFieldLevelEncryptionConfigResult:
        raise NotImplementedError

    @handler("UpdateFieldLevelEncryptionProfile")
    def update_field_level_encryption_profile(
        self,
        context: RequestContext,
        field_level_encryption_profile_config: FieldLevelEncryptionProfileConfig,
        id: string,
        if_match: string = None,
    ) -> UpdateFieldLevelEncryptionProfileResult:
        raise NotImplementedError

    @handler("UpdateFunction")
    def update_function(
        self,
        context: RequestContext,
        if_match: string,
        function_config: FunctionConfig,
        function_code: FunctionBlob,
        name: string,
    ) -> UpdateFunctionResult:
        raise NotImplementedError

    @handler("UpdateKeyGroup")
    def update_key_group(
        self,
        context: RequestContext,
        key_group_config: KeyGroupConfig,
        id: string,
        if_match: string = None,
    ) -> UpdateKeyGroupResult:
        raise NotImplementedError

    @handler("UpdateOriginRequestPolicy")
    def update_origin_request_policy(
        self,
        context: RequestContext,
        origin_request_policy_config: OriginRequestPolicyConfig,
        id: string,
        if_match: string = None,
    ) -> UpdateOriginRequestPolicyResult:
        raise NotImplementedError

    @handler("UpdatePublicKey")
    def update_public_key(
        self,
        context: RequestContext,
        public_key_config: PublicKeyConfig,
        id: string,
        if_match: string = None,
    ) -> UpdatePublicKeyResult:
        raise NotImplementedError

    @handler("UpdateRealtimeLogConfig")
    def update_realtime_log_config(
        self,
        context: RequestContext,
        end_points: EndPointList = None,
        fields: FieldList = None,
        name: string = None,
        arn: string = None,
        sampling_rate: long = None,
    ) -> UpdateRealtimeLogConfigResult:
        raise NotImplementedError

    @handler("UpdateResponseHeadersPolicy")
    def update_response_headers_policy(
        self,
        context: RequestContext,
        response_headers_policy_config: ResponseHeadersPolicyConfig,
        id: string,
        if_match: string = None,
    ) -> UpdateResponseHeadersPolicyResult:
        raise NotImplementedError

    @handler("UpdateStreamingDistribution")
    def update_streaming_distribution(
        self,
        context: RequestContext,
        streaming_distribution_config: StreamingDistributionConfig,
        id: string,
        if_match: string = None,
    ) -> UpdateStreamingDistributionResult:
        raise NotImplementedError
