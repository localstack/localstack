import sys
from datetime import datetime
from typing import List, Optional

if sys.version_info >= (3, 8):
    from typing import TypedDict
else:
    from typing_extensions import TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

AWSAccountID = str
AlarmName = str
AliasHealthEnabled = bool
AssociateVPCComment = str
CloudWatchLogsLogGroupArn = str
DNSName = str
DNSRCode = str
DimensionField = str
Disabled = bool
DisassociateVPCComment = str
EnableSNI = bool
ErrorMessage = str
EvaluationPeriods = int
FailureThreshold = int
FullyQualifiedDomainName = str
GeoLocationContinentCode = str
GeoLocationContinentName = str
GeoLocationCountryCode = str
GeoLocationCountryName = str
GeoLocationSubdivisionCode = str
GeoLocationSubdivisionName = str
HealthCheckId = str
HealthCheckNonce = str
HealthThreshold = int
HostedZoneOwningService = str
IPAddress = str
IPAddressCidr = str
Inverted = bool
IsPrivateZone = bool
MaxResults = str
MeasureLatency = bool
Message = str
MetricName = str
Nameserver = str
Namespace = str
Nonce = str
PageMarker = str
PageMaxItems = str
PageTruncated = bool
PaginationToken = str
Period = int
Port = int
QueryLoggingConfigId = str
RData = str
RecordDataEntry = str
RequestInterval = int
ResourceDescription = str
ResourceId = str
ResourcePath = str
ResourceRecordSetIdentifier = str
ResourceRecordSetMultiValueAnswer = bool
ResourceURI = str
RoutingControlArn = str
SearchString = str
ServeSignature = str
ServicePrincipal = str
SigningKeyInteger = int
SigningKeyName = str
SigningKeyStatus = str
SigningKeyStatusMessage = str
SigningKeyString = str
SigningKeyTag = int
Status = str
SubnetMask = str
TagKey = str
TagResourceId = str
TagValue = str
Threshold = float
TrafficPolicyComment = str
TrafficPolicyDocument = str
TrafficPolicyId = str
TrafficPolicyInstanceCount = int
TrafficPolicyInstanceId = str
TrafficPolicyInstanceState = str
TrafficPolicyName = str
TrafficPolicyVersion = int
TrafficPolicyVersionMarker = str
TransportProtocol = str
VPCId = str


class AccountLimitType(str):
    MAX_HEALTH_CHECKS_BY_OWNER = "MAX_HEALTH_CHECKS_BY_OWNER"
    MAX_HOSTED_ZONES_BY_OWNER = "MAX_HOSTED_ZONES_BY_OWNER"
    MAX_TRAFFIC_POLICY_INSTANCES_BY_OWNER = "MAX_TRAFFIC_POLICY_INSTANCES_BY_OWNER"
    MAX_REUSABLE_DELEGATION_SETS_BY_OWNER = "MAX_REUSABLE_DELEGATION_SETS_BY_OWNER"
    MAX_TRAFFIC_POLICIES_BY_OWNER = "MAX_TRAFFIC_POLICIES_BY_OWNER"


class ChangeAction(str):
    CREATE = "CREATE"
    DELETE = "DELETE"
    UPSERT = "UPSERT"


class ChangeStatus(str):
    PENDING = "PENDING"
    INSYNC = "INSYNC"


class CloudWatchRegion(str):
    us_east_1 = "us-east-1"
    us_east_2 = "us-east-2"
    us_west_1 = "us-west-1"
    us_west_2 = "us-west-2"
    ca_central_1 = "ca-central-1"
    eu_central_1 = "eu-central-1"
    eu_west_1 = "eu-west-1"
    eu_west_2 = "eu-west-2"
    eu_west_3 = "eu-west-3"
    ap_east_1 = "ap-east-1"
    me_south_1 = "me-south-1"
    ap_south_1 = "ap-south-1"
    ap_southeast_1 = "ap-southeast-1"
    ap_southeast_2 = "ap-southeast-2"
    ap_southeast_3 = "ap-southeast-3"
    ap_northeast_1 = "ap-northeast-1"
    ap_northeast_2 = "ap-northeast-2"
    ap_northeast_3 = "ap-northeast-3"
    eu_north_1 = "eu-north-1"
    sa_east_1 = "sa-east-1"
    cn_northwest_1 = "cn-northwest-1"
    cn_north_1 = "cn-north-1"
    af_south_1 = "af-south-1"
    eu_south_1 = "eu-south-1"
    us_gov_west_1 = "us-gov-west-1"
    us_gov_east_1 = "us-gov-east-1"
    us_iso_east_1 = "us-iso-east-1"
    us_iso_west_1 = "us-iso-west-1"
    us_isob_east_1 = "us-isob-east-1"


class ComparisonOperator(str):
    GreaterThanOrEqualToThreshold = "GreaterThanOrEqualToThreshold"
    GreaterThanThreshold = "GreaterThanThreshold"
    LessThanThreshold = "LessThanThreshold"
    LessThanOrEqualToThreshold = "LessThanOrEqualToThreshold"


class HealthCheckRegion(str):
    us_east_1 = "us-east-1"
    us_west_1 = "us-west-1"
    us_west_2 = "us-west-2"
    eu_west_1 = "eu-west-1"
    ap_southeast_1 = "ap-southeast-1"
    ap_southeast_2 = "ap-southeast-2"
    ap_northeast_1 = "ap-northeast-1"
    sa_east_1 = "sa-east-1"


class HealthCheckType(str):
    HTTP = "HTTP"
    HTTPS = "HTTPS"
    HTTP_STR_MATCH = "HTTP_STR_MATCH"
    HTTPS_STR_MATCH = "HTTPS_STR_MATCH"
    TCP = "TCP"
    CALCULATED = "CALCULATED"
    CLOUDWATCH_METRIC = "CLOUDWATCH_METRIC"
    RECOVERY_CONTROL = "RECOVERY_CONTROL"


class HostedZoneLimitType(str):
    MAX_RRSETS_BY_ZONE = "MAX_RRSETS_BY_ZONE"
    MAX_VPCS_ASSOCIATED_BY_ZONE = "MAX_VPCS_ASSOCIATED_BY_ZONE"


class InsufficientDataHealthStatus(str):
    Healthy = "Healthy"
    Unhealthy = "Unhealthy"
    LastKnownStatus = "LastKnownStatus"


class RRType(str):
    SOA = "SOA"
    A = "A"
    TXT = "TXT"
    NS = "NS"
    CNAME = "CNAME"
    MX = "MX"
    NAPTR = "NAPTR"
    PTR = "PTR"
    SRV = "SRV"
    SPF = "SPF"
    AAAA = "AAAA"
    CAA = "CAA"
    DS = "DS"


class ResettableElementName(str):
    FullyQualifiedDomainName = "FullyQualifiedDomainName"
    Regions = "Regions"
    ResourcePath = "ResourcePath"
    ChildHealthChecks = "ChildHealthChecks"


class ResourceRecordSetFailover(str):
    PRIMARY = "PRIMARY"
    SECONDARY = "SECONDARY"


class ResourceRecordSetRegion(str):
    us_east_1 = "us-east-1"
    us_east_2 = "us-east-2"
    us_west_1 = "us-west-1"
    us_west_2 = "us-west-2"
    ca_central_1 = "ca-central-1"
    eu_west_1 = "eu-west-1"
    eu_west_2 = "eu-west-2"
    eu_west_3 = "eu-west-3"
    eu_central_1 = "eu-central-1"
    ap_southeast_1 = "ap-southeast-1"
    ap_southeast_2 = "ap-southeast-2"
    ap_southeast_3 = "ap-southeast-3"
    ap_northeast_1 = "ap-northeast-1"
    ap_northeast_2 = "ap-northeast-2"
    ap_northeast_3 = "ap-northeast-3"
    eu_north_1 = "eu-north-1"
    sa_east_1 = "sa-east-1"
    cn_north_1 = "cn-north-1"
    cn_northwest_1 = "cn-northwest-1"
    ap_east_1 = "ap-east-1"
    me_south_1 = "me-south-1"
    ap_south_1 = "ap-south-1"
    af_south_1 = "af-south-1"
    eu_south_1 = "eu-south-1"


class ReusableDelegationSetLimitType(str):
    MAX_ZONES_BY_REUSABLE_DELEGATION_SET = "MAX_ZONES_BY_REUSABLE_DELEGATION_SET"


class Statistic(str):
    Average = "Average"
    Sum = "Sum"
    SampleCount = "SampleCount"
    Maximum = "Maximum"
    Minimum = "Minimum"


class TagResourceType(str):
    healthcheck = "healthcheck"
    hostedzone = "hostedzone"


class VPCRegion(str):
    us_east_1 = "us-east-1"
    us_east_2 = "us-east-2"
    us_west_1 = "us-west-1"
    us_west_2 = "us-west-2"
    eu_west_1 = "eu-west-1"
    eu_west_2 = "eu-west-2"
    eu_west_3 = "eu-west-3"
    eu_central_1 = "eu-central-1"
    ap_east_1 = "ap-east-1"
    me_south_1 = "me-south-1"
    us_gov_west_1 = "us-gov-west-1"
    us_gov_east_1 = "us-gov-east-1"
    us_iso_east_1 = "us-iso-east-1"
    us_iso_west_1 = "us-iso-west-1"
    us_isob_east_1 = "us-isob-east-1"
    ap_southeast_1 = "ap-southeast-1"
    ap_southeast_2 = "ap-southeast-2"
    ap_southeast_3 = "ap-southeast-3"
    ap_south_1 = "ap-south-1"
    ap_northeast_1 = "ap-northeast-1"
    ap_northeast_2 = "ap-northeast-2"
    ap_northeast_3 = "ap-northeast-3"
    eu_north_1 = "eu-north-1"
    sa_east_1 = "sa-east-1"
    ca_central_1 = "ca-central-1"
    cn_north_1 = "cn-north-1"
    af_south_1 = "af-south-1"
    eu_south_1 = "eu-south-1"


class ConcurrentModification(ServiceException):
    message: Optional[ErrorMessage]


class ConflictingDomainExists(ServiceException):
    message: Optional[ErrorMessage]


class ConflictingTypes(ServiceException):
    message: Optional[ErrorMessage]


class DNSSECNotFound(ServiceException):
    message: Optional[ErrorMessage]


class DelegationSetAlreadyCreated(ServiceException):
    message: Optional[ErrorMessage]


class DelegationSetAlreadyReusable(ServiceException):
    message: Optional[ErrorMessage]


class DelegationSetInUse(ServiceException):
    message: Optional[ErrorMessage]


class DelegationSetNotAvailable(ServiceException):
    message: Optional[ErrorMessage]


class DelegationSetNotReusable(ServiceException):
    message: Optional[ErrorMessage]


class HealthCheckAlreadyExists(ServiceException):
    message: Optional[ErrorMessage]


class HealthCheckInUse(ServiceException):
    message: Optional[ErrorMessage]


class HealthCheckVersionMismatch(ServiceException):
    message: Optional[ErrorMessage]


class HostedZoneAlreadyExists(ServiceException):
    message: Optional[ErrorMessage]


class HostedZoneNotEmpty(ServiceException):
    message: Optional[ErrorMessage]


class HostedZoneNotFound(ServiceException):
    message: Optional[ErrorMessage]


class HostedZoneNotPrivate(ServiceException):
    message: Optional[ErrorMessage]


class HostedZonePartiallyDelegated(ServiceException):
    message: Optional[ErrorMessage]


class IncompatibleVersion(ServiceException):
    message: Optional[ErrorMessage]


class InsufficientCloudWatchLogsResourcePolicy(ServiceException):
    message: Optional[ErrorMessage]


class InvalidArgument(ServiceException):
    message: Optional[ErrorMessage]


ErrorMessages = List[ErrorMessage]


class InvalidChangeBatch(ServiceException):
    messages: Optional[ErrorMessages]
    message: Optional[ErrorMessage]


class InvalidDomainName(ServiceException):
    message: Optional[ErrorMessage]


class InvalidInput(ServiceException):
    message: Optional[ErrorMessage]


class InvalidKMSArn(ServiceException):
    message: Optional[ErrorMessage]


class InvalidKeySigningKeyName(ServiceException):
    message: Optional[ErrorMessage]


class InvalidKeySigningKeyStatus(ServiceException):
    message: Optional[ErrorMessage]


class InvalidPaginationToken(ServiceException):
    message: Optional[ErrorMessage]


class InvalidSigningStatus(ServiceException):
    message: Optional[ErrorMessage]


class InvalidTrafficPolicyDocument(ServiceException):
    message: Optional[ErrorMessage]


class InvalidVPCId(ServiceException):
    message: Optional[ErrorMessage]


class KeySigningKeyAlreadyExists(ServiceException):
    message: Optional[ErrorMessage]


class KeySigningKeyInParentDSRecord(ServiceException):
    message: Optional[ErrorMessage]


class KeySigningKeyInUse(ServiceException):
    message: Optional[ErrorMessage]


class KeySigningKeyWithActiveStatusNotFound(ServiceException):
    message: Optional[ErrorMessage]


class LastVPCAssociation(ServiceException):
    message: Optional[ErrorMessage]


class LimitsExceeded(ServiceException):
    message: Optional[ErrorMessage]


class NoSuchChange(ServiceException):
    message: Optional[ErrorMessage]


class NoSuchCloudWatchLogsLogGroup(ServiceException):
    message: Optional[ErrorMessage]


class NoSuchDelegationSet(ServiceException):
    message: Optional[ErrorMessage]


class NoSuchGeoLocation(ServiceException):
    message: Optional[ErrorMessage]


class NoSuchHealthCheck(ServiceException):
    message: Optional[ErrorMessage]


class NoSuchHostedZone(ServiceException):
    message: Optional[ErrorMessage]


class NoSuchKeySigningKey(ServiceException):
    message: Optional[ErrorMessage]


class NoSuchQueryLoggingConfig(ServiceException):
    message: Optional[ErrorMessage]


class NoSuchTrafficPolicy(ServiceException):
    message: Optional[ErrorMessage]


class NoSuchTrafficPolicyInstance(ServiceException):
    message: Optional[ErrorMessage]


class NotAuthorizedException(ServiceException):
    message: Optional[ErrorMessage]


class PriorRequestNotComplete(ServiceException):
    message: Optional[ErrorMessage]


class PublicZoneVPCAssociation(ServiceException):
    message: Optional[ErrorMessage]


class QueryLoggingConfigAlreadyExists(ServiceException):
    message: Optional[ErrorMessage]


class ThrottlingException(ServiceException):
    message: Optional[ErrorMessage]


class TooManyHealthChecks(ServiceException):
    message: Optional[ErrorMessage]


class TooManyHostedZones(ServiceException):
    message: Optional[ErrorMessage]


class TooManyKeySigningKeys(ServiceException):
    message: Optional[ErrorMessage]


class TooManyTrafficPolicies(ServiceException):
    message: Optional[ErrorMessage]


class TooManyTrafficPolicyInstances(ServiceException):
    message: Optional[ErrorMessage]


class TooManyTrafficPolicyVersionsForCurrentPolicy(ServiceException):
    message: Optional[ErrorMessage]


class TooManyVPCAssociationAuthorizations(ServiceException):
    message: Optional[ErrorMessage]


class TrafficPolicyAlreadyExists(ServiceException):
    message: Optional[ErrorMessage]


class TrafficPolicyInUse(ServiceException):
    message: Optional[ErrorMessage]


class TrafficPolicyInstanceAlreadyExists(ServiceException):
    message: Optional[ErrorMessage]


class VPCAssociationAuthorizationNotFound(ServiceException):
    message: Optional[ErrorMessage]


class VPCAssociationNotFound(ServiceException):
    message: Optional[ErrorMessage]


LimitValue = int


class AccountLimit(TypedDict, total=False):
    Type: AccountLimitType
    Value: LimitValue


class ActivateKeySigningKeyRequest(ServiceRequest):
    HostedZoneId: ResourceId
    Name: SigningKeyName


TimeStamp = datetime


class ChangeInfo(TypedDict, total=False):
    Id: ResourceId
    Status: ChangeStatus
    SubmittedAt: TimeStamp
    Comment: Optional[ResourceDescription]


class ActivateKeySigningKeyResponse(TypedDict, total=False):
    ChangeInfo: ChangeInfo


class AlarmIdentifier(TypedDict, total=False):
    Region: CloudWatchRegion
    Name: AlarmName


class AliasTarget(TypedDict, total=False):
    HostedZoneId: ResourceId
    DNSName: DNSName
    EvaluateTargetHealth: AliasHealthEnabled


class VPC(TypedDict, total=False):
    VPCRegion: Optional[VPCRegion]
    VPCId: Optional[VPCId]


class AssociateVPCWithHostedZoneRequest(ServiceRequest):
    HostedZoneId: ResourceId
    VPC: VPC
    Comment: Optional[AssociateVPCComment]


class AssociateVPCWithHostedZoneResponse(TypedDict, total=False):
    ChangeInfo: ChangeInfo


class ResourceRecord(TypedDict, total=False):
    Value: RData


ResourceRecords = List[ResourceRecord]
TTL = int


class GeoLocation(TypedDict, total=False):
    ContinentCode: Optional[GeoLocationContinentCode]
    CountryCode: Optional[GeoLocationCountryCode]
    SubdivisionCode: Optional[GeoLocationSubdivisionCode]


ResourceRecordSetWeight = int


class ResourceRecordSet(TypedDict, total=False):
    Name: DNSName
    Type: RRType
    SetIdentifier: Optional[ResourceRecordSetIdentifier]
    Weight: Optional[ResourceRecordSetWeight]
    Region: Optional[ResourceRecordSetRegion]
    GeoLocation: Optional[GeoLocation]
    Failover: Optional[ResourceRecordSetFailover]
    MultiValueAnswer: Optional[ResourceRecordSetMultiValueAnswer]
    TTL: Optional[TTL]
    ResourceRecords: Optional[ResourceRecords]
    AliasTarget: Optional[AliasTarget]
    HealthCheckId: Optional[HealthCheckId]
    TrafficPolicyInstanceId: Optional[TrafficPolicyInstanceId]


class Change(TypedDict, total=False):
    Action: ChangeAction
    ResourceRecordSet: ResourceRecordSet


Changes = List[Change]


class ChangeBatch(TypedDict, total=False):
    Comment: Optional[ResourceDescription]
    Changes: Changes


class ChangeResourceRecordSetsRequest(ServiceRequest):
    HostedZoneId: ResourceId
    ChangeBatch: ChangeBatch


class ChangeResourceRecordSetsResponse(TypedDict, total=False):
    ChangeInfo: ChangeInfo


TagKeyList = List[TagKey]


class Tag(TypedDict, total=False):
    Key: Optional[TagKey]
    Value: Optional[TagValue]


TagList = List[Tag]


class ChangeTagsForResourceRequest(ServiceRequest):
    ResourceType: TagResourceType
    ResourceId: TagResourceId
    AddTags: Optional[TagList]
    RemoveTagKeys: Optional[TagKeyList]


class ChangeTagsForResourceResponse(TypedDict, total=False):
    pass


CheckerIpRanges = List[IPAddressCidr]
ChildHealthCheckList = List[HealthCheckId]


class Dimension(TypedDict, total=False):
    Name: DimensionField
    Value: DimensionField


DimensionList = List[Dimension]


class CloudWatchAlarmConfiguration(TypedDict, total=False):
    EvaluationPeriods: EvaluationPeriods
    Threshold: Threshold
    ComparisonOperator: ComparisonOperator
    Period: Period
    MetricName: MetricName
    Namespace: Namespace
    Statistic: Statistic
    Dimensions: Optional[DimensionList]


HealthCheckRegionList = List[HealthCheckRegion]


class HealthCheckConfig(TypedDict, total=False):
    IPAddress: Optional[IPAddress]
    Port: Optional[Port]
    Type: HealthCheckType
    ResourcePath: Optional[ResourcePath]
    FullyQualifiedDomainName: Optional[FullyQualifiedDomainName]
    SearchString: Optional[SearchString]
    RequestInterval: Optional[RequestInterval]
    FailureThreshold: Optional[FailureThreshold]
    MeasureLatency: Optional[MeasureLatency]
    Inverted: Optional[Inverted]
    Disabled: Optional[Disabled]
    HealthThreshold: Optional[HealthThreshold]
    ChildHealthChecks: Optional[ChildHealthCheckList]
    EnableSNI: Optional[EnableSNI]
    Regions: Optional[HealthCheckRegionList]
    AlarmIdentifier: Optional[AlarmIdentifier]
    InsufficientDataHealthStatus: Optional[InsufficientDataHealthStatus]
    RoutingControlArn: Optional[RoutingControlArn]


class CreateHealthCheckRequest(ServiceRequest):
    CallerReference: HealthCheckNonce
    HealthCheckConfig: HealthCheckConfig


HealthCheckVersion = int


class LinkedService(TypedDict, total=False):
    ServicePrincipal: Optional[ServicePrincipal]
    Description: Optional[ResourceDescription]


class HealthCheck(TypedDict, total=False):
    Id: HealthCheckId
    CallerReference: HealthCheckNonce
    LinkedService: Optional[LinkedService]
    HealthCheckConfig: HealthCheckConfig
    HealthCheckVersion: HealthCheckVersion
    CloudWatchAlarmConfiguration: Optional[CloudWatchAlarmConfiguration]


class CreateHealthCheckResponse(TypedDict, total=False):
    HealthCheck: HealthCheck
    Location: ResourceURI


class HostedZoneConfig(TypedDict, total=False):
    Comment: Optional[ResourceDescription]
    PrivateZone: Optional[IsPrivateZone]


class CreateHostedZoneRequest(ServiceRequest):
    Name: DNSName
    VPC: Optional[VPC]
    CallerReference: Nonce
    HostedZoneConfig: Optional[HostedZoneConfig]
    DelegationSetId: Optional[ResourceId]


DelegationSetNameServers = List[DNSName]


class DelegationSet(TypedDict, total=False):
    Id: Optional[ResourceId]
    CallerReference: Optional[Nonce]
    NameServers: DelegationSetNameServers


HostedZoneRRSetCount = int


class HostedZone(TypedDict, total=False):
    Id: ResourceId
    Name: DNSName
    CallerReference: Nonce
    Config: Optional[HostedZoneConfig]
    ResourceRecordSetCount: Optional[HostedZoneRRSetCount]
    LinkedService: Optional[LinkedService]


class CreateHostedZoneResponse(TypedDict, total=False):
    HostedZone: HostedZone
    ChangeInfo: ChangeInfo
    DelegationSet: DelegationSet
    VPC: Optional[VPC]
    Location: ResourceURI


class CreateKeySigningKeyRequest(ServiceRequest):
    CallerReference: Nonce
    HostedZoneId: ResourceId
    KeyManagementServiceArn: SigningKeyString
    Name: SigningKeyName
    Status: SigningKeyStatus


class KeySigningKey(TypedDict, total=False):
    Name: Optional[SigningKeyName]
    KmsArn: Optional[SigningKeyString]
    Flag: Optional[SigningKeyInteger]
    SigningAlgorithmMnemonic: Optional[SigningKeyString]
    SigningAlgorithmType: Optional[SigningKeyInteger]
    DigestAlgorithmMnemonic: Optional[SigningKeyString]
    DigestAlgorithmType: Optional[SigningKeyInteger]
    KeyTag: Optional[SigningKeyTag]
    DigestValue: Optional[SigningKeyString]
    PublicKey: Optional[SigningKeyString]
    DSRecord: Optional[SigningKeyString]
    DNSKEYRecord: Optional[SigningKeyString]
    Status: Optional[SigningKeyStatus]
    StatusMessage: Optional[SigningKeyStatusMessage]
    CreatedDate: Optional[TimeStamp]
    LastModifiedDate: Optional[TimeStamp]


class CreateKeySigningKeyResponse(TypedDict, total=False):
    ChangeInfo: ChangeInfo
    KeySigningKey: KeySigningKey
    Location: ResourceURI


class CreateQueryLoggingConfigRequest(ServiceRequest):
    HostedZoneId: ResourceId
    CloudWatchLogsLogGroupArn: CloudWatchLogsLogGroupArn


class QueryLoggingConfig(TypedDict, total=False):
    Id: QueryLoggingConfigId
    HostedZoneId: ResourceId
    CloudWatchLogsLogGroupArn: CloudWatchLogsLogGroupArn


class CreateQueryLoggingConfigResponse(TypedDict, total=False):
    QueryLoggingConfig: QueryLoggingConfig
    Location: ResourceURI


class CreateReusableDelegationSetRequest(ServiceRequest):
    CallerReference: Nonce
    HostedZoneId: Optional[ResourceId]


class CreateReusableDelegationSetResponse(TypedDict, total=False):
    DelegationSet: DelegationSet
    Location: ResourceURI


class CreateTrafficPolicyInstanceRequest(ServiceRequest):
    HostedZoneId: ResourceId
    Name: DNSName
    TTL: TTL
    TrafficPolicyId: TrafficPolicyId
    TrafficPolicyVersion: TrafficPolicyVersion


class TrafficPolicyInstance(TypedDict, total=False):
    Id: TrafficPolicyInstanceId
    HostedZoneId: ResourceId
    Name: DNSName
    TTL: TTL
    State: TrafficPolicyInstanceState
    Message: Message
    TrafficPolicyId: TrafficPolicyId
    TrafficPolicyVersion: TrafficPolicyVersion
    TrafficPolicyType: RRType


class CreateTrafficPolicyInstanceResponse(TypedDict, total=False):
    TrafficPolicyInstance: TrafficPolicyInstance
    Location: ResourceURI


class CreateTrafficPolicyRequest(ServiceRequest):
    Name: TrafficPolicyName
    Document: TrafficPolicyDocument
    Comment: Optional[TrafficPolicyComment]


class TrafficPolicy(TypedDict, total=False):
    Id: TrafficPolicyId
    Version: TrafficPolicyVersion
    Name: TrafficPolicyName
    Type: RRType
    Document: TrafficPolicyDocument
    Comment: Optional[TrafficPolicyComment]


class CreateTrafficPolicyResponse(TypedDict, total=False):
    TrafficPolicy: TrafficPolicy
    Location: ResourceURI


class CreateTrafficPolicyVersionRequest(ServiceRequest):
    Id: TrafficPolicyId
    Document: TrafficPolicyDocument
    Comment: Optional[TrafficPolicyComment]


class CreateTrafficPolicyVersionResponse(TypedDict, total=False):
    TrafficPolicy: TrafficPolicy
    Location: ResourceURI


class CreateVPCAssociationAuthorizationRequest(ServiceRequest):
    HostedZoneId: ResourceId
    VPC: VPC


class CreateVPCAssociationAuthorizationResponse(TypedDict, total=False):
    HostedZoneId: ResourceId
    VPC: VPC


class DNSSECStatus(TypedDict, total=False):
    ServeSignature: Optional[ServeSignature]
    StatusMessage: Optional[SigningKeyStatusMessage]


class DeactivateKeySigningKeyRequest(ServiceRequest):
    HostedZoneId: ResourceId
    Name: SigningKeyName


class DeactivateKeySigningKeyResponse(TypedDict, total=False):
    ChangeInfo: ChangeInfo


DelegationSets = List[DelegationSet]


class DeleteHealthCheckRequest(ServiceRequest):
    HealthCheckId: HealthCheckId


class DeleteHealthCheckResponse(TypedDict, total=False):
    pass


class DeleteHostedZoneRequest(ServiceRequest):
    Id: ResourceId


class DeleteHostedZoneResponse(TypedDict, total=False):
    ChangeInfo: ChangeInfo


class DeleteKeySigningKeyRequest(ServiceRequest):
    HostedZoneId: ResourceId
    Name: SigningKeyName


class DeleteKeySigningKeyResponse(TypedDict, total=False):
    ChangeInfo: ChangeInfo


class DeleteQueryLoggingConfigRequest(ServiceRequest):
    Id: QueryLoggingConfigId


class DeleteQueryLoggingConfigResponse(TypedDict, total=False):
    pass


class DeleteReusableDelegationSetRequest(ServiceRequest):
    Id: ResourceId


class DeleteReusableDelegationSetResponse(TypedDict, total=False):
    pass


class DeleteTrafficPolicyInstanceRequest(ServiceRequest):
    Id: TrafficPolicyInstanceId


class DeleteTrafficPolicyInstanceResponse(TypedDict, total=False):
    pass


class DeleteTrafficPolicyRequest(ServiceRequest):
    Id: TrafficPolicyId
    Version: TrafficPolicyVersion


class DeleteTrafficPolicyResponse(TypedDict, total=False):
    pass


class DeleteVPCAssociationAuthorizationRequest(ServiceRequest):
    HostedZoneId: ResourceId
    VPC: VPC


class DeleteVPCAssociationAuthorizationResponse(TypedDict, total=False):
    pass


class DisableHostedZoneDNSSECRequest(ServiceRequest):
    HostedZoneId: ResourceId


class DisableHostedZoneDNSSECResponse(TypedDict, total=False):
    ChangeInfo: ChangeInfo


class DisassociateVPCFromHostedZoneRequest(ServiceRequest):
    HostedZoneId: ResourceId
    VPC: VPC
    Comment: Optional[DisassociateVPCComment]


class DisassociateVPCFromHostedZoneResponse(TypedDict, total=False):
    ChangeInfo: ChangeInfo


class EnableHostedZoneDNSSECRequest(ServiceRequest):
    HostedZoneId: ResourceId


class EnableHostedZoneDNSSECResponse(TypedDict, total=False):
    ChangeInfo: ChangeInfo


class GeoLocationDetails(TypedDict, total=False):
    ContinentCode: Optional[GeoLocationContinentCode]
    ContinentName: Optional[GeoLocationContinentName]
    CountryCode: Optional[GeoLocationCountryCode]
    CountryName: Optional[GeoLocationCountryName]
    SubdivisionCode: Optional[GeoLocationSubdivisionCode]
    SubdivisionName: Optional[GeoLocationSubdivisionName]


GeoLocationDetailsList = List[GeoLocationDetails]


class GetAccountLimitRequest(ServiceRequest):
    Type: AccountLimitType


UsageCount = int


class GetAccountLimitResponse(TypedDict, total=False):
    Limit: AccountLimit
    Count: UsageCount


class GetChangeRequest(ServiceRequest):
    Id: ResourceId


class GetChangeResponse(TypedDict, total=False):
    ChangeInfo: ChangeInfo


class GetCheckerIpRangesRequest(ServiceRequest):
    pass


class GetCheckerIpRangesResponse(TypedDict, total=False):
    CheckerIpRanges: CheckerIpRanges


class GetDNSSECRequest(ServiceRequest):
    HostedZoneId: ResourceId


KeySigningKeys = List[KeySigningKey]


class GetDNSSECResponse(TypedDict, total=False):
    Status: DNSSECStatus
    KeySigningKeys: KeySigningKeys


class GetGeoLocationRequest(ServiceRequest):
    ContinentCode: Optional[GeoLocationContinentCode]
    CountryCode: Optional[GeoLocationCountryCode]
    SubdivisionCode: Optional[GeoLocationSubdivisionCode]


class GetGeoLocationResponse(TypedDict, total=False):
    GeoLocationDetails: GeoLocationDetails


class GetHealthCheckCountRequest(ServiceRequest):
    pass


HealthCheckCount = int


class GetHealthCheckCountResponse(TypedDict, total=False):
    HealthCheckCount: HealthCheckCount


class GetHealthCheckLastFailureReasonRequest(ServiceRequest):
    HealthCheckId: HealthCheckId


class StatusReport(TypedDict, total=False):
    Status: Optional[Status]
    CheckedTime: Optional[TimeStamp]


class HealthCheckObservation(TypedDict, total=False):
    Region: Optional[HealthCheckRegion]
    IPAddress: Optional[IPAddress]
    StatusReport: Optional[StatusReport]


HealthCheckObservations = List[HealthCheckObservation]


class GetHealthCheckLastFailureReasonResponse(TypedDict, total=False):
    HealthCheckObservations: HealthCheckObservations


class GetHealthCheckRequest(ServiceRequest):
    HealthCheckId: HealthCheckId


class GetHealthCheckResponse(TypedDict, total=False):
    HealthCheck: HealthCheck


class GetHealthCheckStatusRequest(ServiceRequest):
    HealthCheckId: HealthCheckId


class GetHealthCheckStatusResponse(TypedDict, total=False):
    HealthCheckObservations: HealthCheckObservations


class GetHostedZoneCountRequest(ServiceRequest):
    pass


HostedZoneCount = int


class GetHostedZoneCountResponse(TypedDict, total=False):
    HostedZoneCount: HostedZoneCount


class GetHostedZoneLimitRequest(ServiceRequest):
    Type: HostedZoneLimitType
    HostedZoneId: ResourceId


class HostedZoneLimit(TypedDict, total=False):
    Type: HostedZoneLimitType
    Value: LimitValue


class GetHostedZoneLimitResponse(TypedDict, total=False):
    Limit: HostedZoneLimit
    Count: UsageCount


class GetHostedZoneRequest(ServiceRequest):
    Id: ResourceId


VPCs = List[VPC]


class GetHostedZoneResponse(TypedDict, total=False):
    HostedZone: HostedZone
    DelegationSet: Optional[DelegationSet]
    VPCs: Optional[VPCs]


class GetQueryLoggingConfigRequest(ServiceRequest):
    Id: QueryLoggingConfigId


class GetQueryLoggingConfigResponse(TypedDict, total=False):
    QueryLoggingConfig: QueryLoggingConfig


class GetReusableDelegationSetLimitRequest(ServiceRequest):
    Type: ReusableDelegationSetLimitType
    DelegationSetId: ResourceId


class ReusableDelegationSetLimit(TypedDict, total=False):
    Type: ReusableDelegationSetLimitType
    Value: LimitValue


class GetReusableDelegationSetLimitResponse(TypedDict, total=False):
    Limit: ReusableDelegationSetLimit
    Count: UsageCount


class GetReusableDelegationSetRequest(ServiceRequest):
    Id: ResourceId


class GetReusableDelegationSetResponse(TypedDict, total=False):
    DelegationSet: DelegationSet


class GetTrafficPolicyInstanceCountRequest(ServiceRequest):
    pass


class GetTrafficPolicyInstanceCountResponse(TypedDict, total=False):
    TrafficPolicyInstanceCount: TrafficPolicyInstanceCount


class GetTrafficPolicyInstanceRequest(ServiceRequest):
    Id: TrafficPolicyInstanceId


class GetTrafficPolicyInstanceResponse(TypedDict, total=False):
    TrafficPolicyInstance: TrafficPolicyInstance


class GetTrafficPolicyRequest(ServiceRequest):
    Id: TrafficPolicyId
    Version: TrafficPolicyVersion


class GetTrafficPolicyResponse(TypedDict, total=False):
    TrafficPolicy: TrafficPolicy


HealthChecks = List[HealthCheck]


class HostedZoneOwner(TypedDict, total=False):
    OwningAccount: Optional[AWSAccountID]
    OwningService: Optional[HostedZoneOwningService]


class HostedZoneSummary(TypedDict, total=False):
    HostedZoneId: ResourceId
    Name: DNSName
    Owner: HostedZoneOwner


HostedZoneSummaries = List[HostedZoneSummary]
HostedZones = List[HostedZone]


class ListGeoLocationsRequest(ServiceRequest):
    StartContinentCode: Optional[GeoLocationContinentCode]
    StartCountryCode: Optional[GeoLocationCountryCode]
    StartSubdivisionCode: Optional[GeoLocationSubdivisionCode]
    MaxItems: Optional[PageMaxItems]


class ListGeoLocationsResponse(TypedDict, total=False):
    GeoLocationDetailsList: GeoLocationDetailsList
    IsTruncated: PageTruncated
    NextContinentCode: Optional[GeoLocationContinentCode]
    NextCountryCode: Optional[GeoLocationCountryCode]
    NextSubdivisionCode: Optional[GeoLocationSubdivisionCode]
    MaxItems: PageMaxItems


class ListHealthChecksRequest(ServiceRequest):
    Marker: Optional[PageMarker]
    MaxItems: Optional[PageMaxItems]


class ListHealthChecksResponse(TypedDict, total=False):
    HealthChecks: HealthChecks
    Marker: PageMarker
    IsTruncated: PageTruncated
    NextMarker: Optional[PageMarker]
    MaxItems: PageMaxItems


class ListHostedZonesByNameRequest(ServiceRequest):
    DNSName: Optional[DNSName]
    HostedZoneId: Optional[ResourceId]
    MaxItems: Optional[PageMaxItems]


class ListHostedZonesByNameResponse(TypedDict, total=False):
    HostedZones: HostedZones
    DNSName: Optional[DNSName]
    HostedZoneId: Optional[ResourceId]
    IsTruncated: PageTruncated
    NextDNSName: Optional[DNSName]
    NextHostedZoneId: Optional[ResourceId]
    MaxItems: PageMaxItems


class ListHostedZonesByVPCRequest(ServiceRequest):
    VPCId: VPCId
    VPCRegion: VPCRegion
    MaxItems: Optional[PageMaxItems]
    NextToken: Optional[PaginationToken]


class ListHostedZonesByVPCResponse(TypedDict, total=False):
    HostedZoneSummaries: HostedZoneSummaries
    MaxItems: PageMaxItems
    NextToken: Optional[PaginationToken]


class ListHostedZonesRequest(ServiceRequest):
    Marker: Optional[PageMarker]
    MaxItems: Optional[PageMaxItems]
    DelegationSetId: Optional[ResourceId]


class ListHostedZonesResponse(TypedDict, total=False):
    HostedZones: HostedZones
    Marker: PageMarker
    IsTruncated: PageTruncated
    NextMarker: Optional[PageMarker]
    MaxItems: PageMaxItems


class ListQueryLoggingConfigsRequest(ServiceRequest):
    HostedZoneId: Optional[ResourceId]
    NextToken: Optional[PaginationToken]
    MaxResults: Optional[MaxResults]


QueryLoggingConfigs = List[QueryLoggingConfig]


class ListQueryLoggingConfigsResponse(TypedDict, total=False):
    QueryLoggingConfigs: QueryLoggingConfigs
    NextToken: Optional[PaginationToken]


class ListResourceRecordSetsRequest(ServiceRequest):
    HostedZoneId: ResourceId
    StartRecordName: Optional[DNSName]
    StartRecordType: Optional[RRType]
    StartRecordIdentifier: Optional[ResourceRecordSetIdentifier]
    MaxItems: Optional[PageMaxItems]


ResourceRecordSets = List[ResourceRecordSet]


class ListResourceRecordSetsResponse(TypedDict, total=False):
    ResourceRecordSets: ResourceRecordSets
    IsTruncated: PageTruncated
    NextRecordName: Optional[DNSName]
    NextRecordType: Optional[RRType]
    NextRecordIdentifier: Optional[ResourceRecordSetIdentifier]
    MaxItems: PageMaxItems


class ListReusableDelegationSetsRequest(ServiceRequest):
    Marker: Optional[PageMarker]
    MaxItems: Optional[PageMaxItems]


class ListReusableDelegationSetsResponse(TypedDict, total=False):
    DelegationSets: DelegationSets
    Marker: PageMarker
    IsTruncated: PageTruncated
    NextMarker: Optional[PageMarker]
    MaxItems: PageMaxItems


class ListTagsForResourceRequest(ServiceRequest):
    ResourceType: TagResourceType
    ResourceId: TagResourceId


class ResourceTagSet(TypedDict, total=False):
    ResourceType: Optional[TagResourceType]
    ResourceId: Optional[TagResourceId]
    Tags: Optional[TagList]


class ListTagsForResourceResponse(TypedDict, total=False):
    ResourceTagSet: ResourceTagSet


TagResourceIdList = List[TagResourceId]


class ListTagsForResourcesRequest(ServiceRequest):
    ResourceType: TagResourceType
    ResourceIds: TagResourceIdList


ResourceTagSetList = List[ResourceTagSet]


class ListTagsForResourcesResponse(TypedDict, total=False):
    ResourceTagSets: ResourceTagSetList


class ListTrafficPoliciesRequest(ServiceRequest):
    TrafficPolicyIdMarker: Optional[TrafficPolicyId]
    MaxItems: Optional[PageMaxItems]


class TrafficPolicySummary(TypedDict, total=False):
    Id: TrafficPolicyId
    Name: TrafficPolicyName
    Type: RRType
    LatestVersion: TrafficPolicyVersion
    TrafficPolicyCount: TrafficPolicyVersion


TrafficPolicySummaries = List[TrafficPolicySummary]


class ListTrafficPoliciesResponse(TypedDict, total=False):
    TrafficPolicySummaries: TrafficPolicySummaries
    IsTruncated: PageTruncated
    TrafficPolicyIdMarker: TrafficPolicyId
    MaxItems: PageMaxItems


class ListTrafficPolicyInstancesByHostedZoneRequest(ServiceRequest):
    HostedZoneId: ResourceId
    TrafficPolicyInstanceNameMarker: Optional[DNSName]
    TrafficPolicyInstanceTypeMarker: Optional[RRType]
    MaxItems: Optional[PageMaxItems]


TrafficPolicyInstances = List[TrafficPolicyInstance]


class ListTrafficPolicyInstancesByHostedZoneResponse(TypedDict, total=False):
    TrafficPolicyInstances: TrafficPolicyInstances
    TrafficPolicyInstanceNameMarker: Optional[DNSName]
    TrafficPolicyInstanceTypeMarker: Optional[RRType]
    IsTruncated: PageTruncated
    MaxItems: PageMaxItems


class ListTrafficPolicyInstancesByPolicyRequest(ServiceRequest):
    TrafficPolicyId: TrafficPolicyId
    TrafficPolicyVersion: TrafficPolicyVersion
    HostedZoneIdMarker: Optional[ResourceId]
    TrafficPolicyInstanceNameMarker: Optional[DNSName]
    TrafficPolicyInstanceTypeMarker: Optional[RRType]
    MaxItems: Optional[PageMaxItems]


class ListTrafficPolicyInstancesByPolicyResponse(TypedDict, total=False):
    TrafficPolicyInstances: TrafficPolicyInstances
    HostedZoneIdMarker: Optional[ResourceId]
    TrafficPolicyInstanceNameMarker: Optional[DNSName]
    TrafficPolicyInstanceTypeMarker: Optional[RRType]
    IsTruncated: PageTruncated
    MaxItems: PageMaxItems


class ListTrafficPolicyInstancesRequest(ServiceRequest):
    HostedZoneIdMarker: Optional[ResourceId]
    TrafficPolicyInstanceNameMarker: Optional[DNSName]
    TrafficPolicyInstanceTypeMarker: Optional[RRType]
    MaxItems: Optional[PageMaxItems]


class ListTrafficPolicyInstancesResponse(TypedDict, total=False):
    TrafficPolicyInstances: TrafficPolicyInstances
    HostedZoneIdMarker: Optional[ResourceId]
    TrafficPolicyInstanceNameMarker: Optional[DNSName]
    TrafficPolicyInstanceTypeMarker: Optional[RRType]
    IsTruncated: PageTruncated
    MaxItems: PageMaxItems


class ListTrafficPolicyVersionsRequest(ServiceRequest):
    Id: TrafficPolicyId
    TrafficPolicyVersionMarker: Optional[TrafficPolicyVersionMarker]
    MaxItems: Optional[PageMaxItems]


TrafficPolicies = List[TrafficPolicy]


class ListTrafficPolicyVersionsResponse(TypedDict, total=False):
    TrafficPolicies: TrafficPolicies
    IsTruncated: PageTruncated
    TrafficPolicyVersionMarker: TrafficPolicyVersionMarker
    MaxItems: PageMaxItems


class ListVPCAssociationAuthorizationsRequest(ServiceRequest):
    HostedZoneId: ResourceId
    NextToken: Optional[PaginationToken]
    MaxResults: Optional[MaxResults]


class ListVPCAssociationAuthorizationsResponse(TypedDict, total=False):
    HostedZoneId: ResourceId
    NextToken: Optional[PaginationToken]
    VPCs: VPCs


RecordData = List[RecordDataEntry]
ResettableElementNameList = List[ResettableElementName]


class TestDNSAnswerRequest(ServiceRequest):
    HostedZoneId: ResourceId
    RecordName: DNSName
    RecordType: RRType
    ResolverIP: Optional[IPAddress]
    EDNS0ClientSubnetIP: Optional[IPAddress]
    EDNS0ClientSubnetMask: Optional[SubnetMask]


class TestDNSAnswerResponse(TypedDict, total=False):
    Nameserver: Nameserver
    RecordName: DNSName
    RecordType: RRType
    RecordData: RecordData
    ResponseCode: DNSRCode
    Protocol: TransportProtocol


class UpdateHealthCheckRequest(ServiceRequest):
    HealthCheckId: HealthCheckId
    HealthCheckVersion: Optional[HealthCheckVersion]
    IPAddress: Optional[IPAddress]
    Port: Optional[Port]
    ResourcePath: Optional[ResourcePath]
    FullyQualifiedDomainName: Optional[FullyQualifiedDomainName]
    SearchString: Optional[SearchString]
    FailureThreshold: Optional[FailureThreshold]
    Inverted: Optional[Inverted]
    Disabled: Optional[Disabled]
    HealthThreshold: Optional[HealthThreshold]
    ChildHealthChecks: Optional[ChildHealthCheckList]
    EnableSNI: Optional[EnableSNI]
    Regions: Optional[HealthCheckRegionList]
    AlarmIdentifier: Optional[AlarmIdentifier]
    InsufficientDataHealthStatus: Optional[InsufficientDataHealthStatus]
    ResetElements: Optional[ResettableElementNameList]


class UpdateHealthCheckResponse(TypedDict, total=False):
    HealthCheck: HealthCheck


class UpdateHostedZoneCommentRequest(ServiceRequest):
    Id: ResourceId
    Comment: Optional[ResourceDescription]


class UpdateHostedZoneCommentResponse(TypedDict, total=False):
    HostedZone: HostedZone


class UpdateTrafficPolicyCommentRequest(ServiceRequest):
    Id: TrafficPolicyId
    Version: TrafficPolicyVersion
    Comment: TrafficPolicyComment


class UpdateTrafficPolicyCommentResponse(TypedDict, total=False):
    TrafficPolicy: TrafficPolicy


class UpdateTrafficPolicyInstanceRequest(ServiceRequest):
    Id: TrafficPolicyInstanceId
    TTL: TTL
    TrafficPolicyId: TrafficPolicyId
    TrafficPolicyVersion: TrafficPolicyVersion


class UpdateTrafficPolicyInstanceResponse(TypedDict, total=False):
    TrafficPolicyInstance: TrafficPolicyInstance


class Route53Api:

    service = "route53"
    version = "2013-04-01"

    @handler("ActivateKeySigningKey")
    def activate_key_signing_key(
        self, context: RequestContext, hosted_zone_id: ResourceId, name: SigningKeyName
    ) -> ActivateKeySigningKeyResponse:
        raise NotImplementedError

    @handler("AssociateVPCWithHostedZone")
    def associate_vpc_with_hosted_zone(
        self,
        context: RequestContext,
        hosted_zone_id: ResourceId,
        vpc: VPC,
        comment: AssociateVPCComment = None,
    ) -> AssociateVPCWithHostedZoneResponse:
        raise NotImplementedError

    @handler("ChangeResourceRecordSets")
    def change_resource_record_sets(
        self, context: RequestContext, hosted_zone_id: ResourceId, change_batch: ChangeBatch
    ) -> ChangeResourceRecordSetsResponse:
        raise NotImplementedError

    @handler("ChangeTagsForResource")
    def change_tags_for_resource(
        self,
        context: RequestContext,
        resource_type: TagResourceType,
        resource_id: TagResourceId,
        add_tags: TagList = None,
        remove_tag_keys: TagKeyList = None,
    ) -> ChangeTagsForResourceResponse:
        raise NotImplementedError

    @handler("CreateHealthCheck")
    def create_health_check(
        self,
        context: RequestContext,
        caller_reference: HealthCheckNonce,
        health_check_config: HealthCheckConfig,
    ) -> CreateHealthCheckResponse:
        raise NotImplementedError

    @handler("CreateHostedZone")
    def create_hosted_zone(
        self,
        context: RequestContext,
        name: DNSName,
        caller_reference: Nonce,
        vpc: VPC = None,
        hosted_zone_config: HostedZoneConfig = None,
        delegation_set_id: ResourceId = None,
    ) -> CreateHostedZoneResponse:
        raise NotImplementedError

    @handler("CreateKeySigningKey")
    def create_key_signing_key(
        self,
        context: RequestContext,
        caller_reference: Nonce,
        hosted_zone_id: ResourceId,
        key_management_service_arn: SigningKeyString,
        name: SigningKeyName,
        status: SigningKeyStatus,
    ) -> CreateKeySigningKeyResponse:
        raise NotImplementedError

    @handler("CreateQueryLoggingConfig")
    def create_query_logging_config(
        self,
        context: RequestContext,
        hosted_zone_id: ResourceId,
        cloud_watch_logs_log_group_arn: CloudWatchLogsLogGroupArn,
    ) -> CreateQueryLoggingConfigResponse:
        raise NotImplementedError

    @handler("CreateReusableDelegationSet")
    def create_reusable_delegation_set(
        self, context: RequestContext, caller_reference: Nonce, hosted_zone_id: ResourceId = None
    ) -> CreateReusableDelegationSetResponse:
        raise NotImplementedError

    @handler("CreateTrafficPolicy")
    def create_traffic_policy(
        self,
        context: RequestContext,
        name: TrafficPolicyName,
        document: TrafficPolicyDocument,
        comment: TrafficPolicyComment = None,
    ) -> CreateTrafficPolicyResponse:
        raise NotImplementedError

    @handler("CreateTrafficPolicyInstance")
    def create_traffic_policy_instance(
        self,
        context: RequestContext,
        hosted_zone_id: ResourceId,
        name: DNSName,
        ttl: TTL,
        traffic_policy_id: TrafficPolicyId,
        traffic_policy_version: TrafficPolicyVersion,
    ) -> CreateTrafficPolicyInstanceResponse:
        raise NotImplementedError

    @handler("CreateTrafficPolicyVersion")
    def create_traffic_policy_version(
        self,
        context: RequestContext,
        id: TrafficPolicyId,
        document: TrafficPolicyDocument,
        comment: TrafficPolicyComment = None,
    ) -> CreateTrafficPolicyVersionResponse:
        raise NotImplementedError

    @handler("CreateVPCAssociationAuthorization")
    def create_vpc_association_authorization(
        self, context: RequestContext, hosted_zone_id: ResourceId, vpc: VPC
    ) -> CreateVPCAssociationAuthorizationResponse:
        raise NotImplementedError

    @handler("DeactivateKeySigningKey")
    def deactivate_key_signing_key(
        self, context: RequestContext, hosted_zone_id: ResourceId, name: SigningKeyName
    ) -> DeactivateKeySigningKeyResponse:
        raise NotImplementedError

    @handler("DeleteHealthCheck")
    def delete_health_check(
        self, context: RequestContext, health_check_id: HealthCheckId
    ) -> DeleteHealthCheckResponse:
        raise NotImplementedError

    @handler("DeleteHostedZone")
    def delete_hosted_zone(
        self, context: RequestContext, id: ResourceId
    ) -> DeleteHostedZoneResponse:
        raise NotImplementedError

    @handler("DeleteKeySigningKey")
    def delete_key_signing_key(
        self, context: RequestContext, hosted_zone_id: ResourceId, name: SigningKeyName
    ) -> DeleteKeySigningKeyResponse:
        raise NotImplementedError

    @handler("DeleteQueryLoggingConfig")
    def delete_query_logging_config(
        self, context: RequestContext, id: QueryLoggingConfigId
    ) -> DeleteQueryLoggingConfigResponse:
        raise NotImplementedError

    @handler("DeleteReusableDelegationSet")
    def delete_reusable_delegation_set(
        self, context: RequestContext, id: ResourceId
    ) -> DeleteReusableDelegationSetResponse:
        raise NotImplementedError

    @handler("DeleteTrafficPolicy")
    def delete_traffic_policy(
        self, context: RequestContext, id: TrafficPolicyId, version: TrafficPolicyVersion
    ) -> DeleteTrafficPolicyResponse:
        raise NotImplementedError

    @handler("DeleteTrafficPolicyInstance")
    def delete_traffic_policy_instance(
        self, context: RequestContext, id: TrafficPolicyInstanceId
    ) -> DeleteTrafficPolicyInstanceResponse:
        raise NotImplementedError

    @handler("DeleteVPCAssociationAuthorization")
    def delete_vpc_association_authorization(
        self, context: RequestContext, hosted_zone_id: ResourceId, vpc: VPC
    ) -> DeleteVPCAssociationAuthorizationResponse:
        raise NotImplementedError

    @handler("DisableHostedZoneDNSSEC")
    def disable_hosted_zone_dnssec(
        self, context: RequestContext, hosted_zone_id: ResourceId
    ) -> DisableHostedZoneDNSSECResponse:
        raise NotImplementedError

    @handler("DisassociateVPCFromHostedZone")
    def disassociate_vpc_from_hosted_zone(
        self,
        context: RequestContext,
        hosted_zone_id: ResourceId,
        vpc: VPC,
        comment: DisassociateVPCComment = None,
    ) -> DisassociateVPCFromHostedZoneResponse:
        raise NotImplementedError

    @handler("EnableHostedZoneDNSSEC")
    def enable_hosted_zone_dnssec(
        self, context: RequestContext, hosted_zone_id: ResourceId
    ) -> EnableHostedZoneDNSSECResponse:
        raise NotImplementedError

    @handler("GetAccountLimit", expand=False)
    def get_account_limit(
        self, context: RequestContext, request: GetAccountLimitRequest
    ) -> GetAccountLimitResponse:
        raise NotImplementedError

    @handler("GetChange")
    def get_change(self, context: RequestContext, id: ResourceId) -> GetChangeResponse:
        raise NotImplementedError

    @handler("GetCheckerIpRanges")
    def get_checker_ip_ranges(
        self,
        context: RequestContext,
    ) -> GetCheckerIpRangesResponse:
        raise NotImplementedError

    @handler("GetDNSSEC")
    def get_dnssec(self, context: RequestContext, hosted_zone_id: ResourceId) -> GetDNSSECResponse:
        raise NotImplementedError

    @handler("GetGeoLocation")
    def get_geo_location(
        self,
        context: RequestContext,
        continent_code: GeoLocationContinentCode = None,
        country_code: GeoLocationCountryCode = None,
        subdivision_code: GeoLocationSubdivisionCode = None,
    ) -> GetGeoLocationResponse:
        raise NotImplementedError

    @handler("GetHealthCheck")
    def get_health_check(
        self, context: RequestContext, health_check_id: HealthCheckId
    ) -> GetHealthCheckResponse:
        raise NotImplementedError

    @handler("GetHealthCheckCount")
    def get_health_check_count(
        self,
        context: RequestContext,
    ) -> GetHealthCheckCountResponse:
        raise NotImplementedError

    @handler("GetHealthCheckLastFailureReason")
    def get_health_check_last_failure_reason(
        self, context: RequestContext, health_check_id: HealthCheckId
    ) -> GetHealthCheckLastFailureReasonResponse:
        raise NotImplementedError

    @handler("GetHealthCheckStatus")
    def get_health_check_status(
        self, context: RequestContext, health_check_id: HealthCheckId
    ) -> GetHealthCheckStatusResponse:
        raise NotImplementedError

    @handler("GetHostedZone")
    def get_hosted_zone(self, context: RequestContext, id: ResourceId) -> GetHostedZoneResponse:
        raise NotImplementedError

    @handler("GetHostedZoneCount")
    def get_hosted_zone_count(
        self,
        context: RequestContext,
    ) -> GetHostedZoneCountResponse:
        raise NotImplementedError

    @handler("GetHostedZoneLimit", expand=False)
    def get_hosted_zone_limit(
        self, context: RequestContext, request: GetHostedZoneLimitRequest
    ) -> GetHostedZoneLimitResponse:
        raise NotImplementedError

    @handler("GetQueryLoggingConfig")
    def get_query_logging_config(
        self, context: RequestContext, id: QueryLoggingConfigId
    ) -> GetQueryLoggingConfigResponse:
        raise NotImplementedError

    @handler("GetReusableDelegationSet")
    def get_reusable_delegation_set(
        self, context: RequestContext, id: ResourceId
    ) -> GetReusableDelegationSetResponse:
        raise NotImplementedError

    @handler("GetReusableDelegationSetLimit", expand=False)
    def get_reusable_delegation_set_limit(
        self, context: RequestContext, request: GetReusableDelegationSetLimitRequest
    ) -> GetReusableDelegationSetLimitResponse:
        raise NotImplementedError

    @handler("GetTrafficPolicy")
    def get_traffic_policy(
        self, context: RequestContext, id: TrafficPolicyId, version: TrafficPolicyVersion
    ) -> GetTrafficPolicyResponse:
        raise NotImplementedError

    @handler("GetTrafficPolicyInstance")
    def get_traffic_policy_instance(
        self, context: RequestContext, id: TrafficPolicyInstanceId
    ) -> GetTrafficPolicyInstanceResponse:
        raise NotImplementedError

    @handler("GetTrafficPolicyInstanceCount")
    def get_traffic_policy_instance_count(
        self,
        context: RequestContext,
    ) -> GetTrafficPolicyInstanceCountResponse:
        raise NotImplementedError

    @handler("ListGeoLocations")
    def list_geo_locations(
        self,
        context: RequestContext,
        start_continent_code: GeoLocationContinentCode = None,
        start_country_code: GeoLocationCountryCode = None,
        start_subdivision_code: GeoLocationSubdivisionCode = None,
        max_items: PageMaxItems = None,
    ) -> ListGeoLocationsResponse:
        raise NotImplementedError

    @handler("ListHealthChecks")
    def list_health_checks(
        self, context: RequestContext, marker: PageMarker = None, max_items: PageMaxItems = None
    ) -> ListHealthChecksResponse:
        raise NotImplementedError

    @handler("ListHostedZones")
    def list_hosted_zones(
        self,
        context: RequestContext,
        marker: PageMarker = None,
        max_items: PageMaxItems = None,
        delegation_set_id: ResourceId = None,
    ) -> ListHostedZonesResponse:
        raise NotImplementedError

    @handler("ListHostedZonesByName")
    def list_hosted_zones_by_name(
        self,
        context: RequestContext,
        dns_name: DNSName = None,
        hosted_zone_id: ResourceId = None,
        max_items: PageMaxItems = None,
    ) -> ListHostedZonesByNameResponse:
        raise NotImplementedError

    @handler("ListHostedZonesByVPC")
    def list_hosted_zones_by_vpc(
        self,
        context: RequestContext,
        vpc_id: VPCId,
        vpc_region: VPCRegion,
        max_items: PageMaxItems = None,
        next_token: PaginationToken = None,
    ) -> ListHostedZonesByVPCResponse:
        raise NotImplementedError

    @handler("ListQueryLoggingConfigs")
    def list_query_logging_configs(
        self,
        context: RequestContext,
        hosted_zone_id: ResourceId = None,
        next_token: PaginationToken = None,
        max_results: MaxResults = None,
    ) -> ListQueryLoggingConfigsResponse:
        raise NotImplementedError

    @handler("ListResourceRecordSets")
    def list_resource_record_sets(
        self,
        context: RequestContext,
        hosted_zone_id: ResourceId,
        start_record_name: DNSName = None,
        start_record_type: RRType = None,
        start_record_identifier: ResourceRecordSetIdentifier = None,
        max_items: PageMaxItems = None,
    ) -> ListResourceRecordSetsResponse:
        raise NotImplementedError

    @handler("ListReusableDelegationSets")
    def list_reusable_delegation_sets(
        self, context: RequestContext, marker: PageMarker = None, max_items: PageMaxItems = None
    ) -> ListReusableDelegationSetsResponse:
        raise NotImplementedError

    @handler("ListTagsForResource")
    def list_tags_for_resource(
        self, context: RequestContext, resource_type: TagResourceType, resource_id: TagResourceId
    ) -> ListTagsForResourceResponse:
        raise NotImplementedError

    @handler("ListTagsForResources")
    def list_tags_for_resources(
        self,
        context: RequestContext,
        resource_type: TagResourceType,
        resource_ids: TagResourceIdList,
    ) -> ListTagsForResourcesResponse:
        raise NotImplementedError

    @handler("ListTrafficPolicies")
    def list_traffic_policies(
        self,
        context: RequestContext,
        traffic_policy_id_marker: TrafficPolicyId = None,
        max_items: PageMaxItems = None,
    ) -> ListTrafficPoliciesResponse:
        raise NotImplementedError

    @handler("ListTrafficPolicyInstances")
    def list_traffic_policy_instances(
        self,
        context: RequestContext,
        hosted_zone_id_marker: ResourceId = None,
        traffic_policy_instance_name_marker: DNSName = None,
        traffic_policy_instance_type_marker: RRType = None,
        max_items: PageMaxItems = None,
    ) -> ListTrafficPolicyInstancesResponse:
        raise NotImplementedError

    @handler("ListTrafficPolicyInstancesByHostedZone")
    def list_traffic_policy_instances_by_hosted_zone(
        self,
        context: RequestContext,
        hosted_zone_id: ResourceId,
        traffic_policy_instance_name_marker: DNSName = None,
        traffic_policy_instance_type_marker: RRType = None,
        max_items: PageMaxItems = None,
    ) -> ListTrafficPolicyInstancesByHostedZoneResponse:
        raise NotImplementedError

    @handler("ListTrafficPolicyInstancesByPolicy")
    def list_traffic_policy_instances_by_policy(
        self,
        context: RequestContext,
        traffic_policy_id: TrafficPolicyId,
        traffic_policy_version: TrafficPolicyVersion,
        hosted_zone_id_marker: ResourceId = None,
        traffic_policy_instance_name_marker: DNSName = None,
        traffic_policy_instance_type_marker: RRType = None,
        max_items: PageMaxItems = None,
    ) -> ListTrafficPolicyInstancesByPolicyResponse:
        raise NotImplementedError

    @handler("ListTrafficPolicyVersions")
    def list_traffic_policy_versions(
        self,
        context: RequestContext,
        id: TrafficPolicyId,
        traffic_policy_version_marker: TrafficPolicyVersionMarker = None,
        max_items: PageMaxItems = None,
    ) -> ListTrafficPolicyVersionsResponse:
        raise NotImplementedError

    @handler("ListVPCAssociationAuthorizations")
    def list_vpc_association_authorizations(
        self,
        context: RequestContext,
        hosted_zone_id: ResourceId,
        next_token: PaginationToken = None,
        max_results: MaxResults = None,
    ) -> ListVPCAssociationAuthorizationsResponse:
        raise NotImplementedError

    @handler("TestDNSAnswer")
    def test_dns_answer(
        self,
        context: RequestContext,
        hosted_zone_id: ResourceId,
        record_name: DNSName,
        record_type: RRType,
        resolver_ip: IPAddress = None,
        edns0_client_subnet_ip: IPAddress = None,
        edns0_client_subnet_mask: SubnetMask = None,
    ) -> TestDNSAnswerResponse:
        raise NotImplementedError

    @handler("UpdateHealthCheck")
    def update_health_check(
        self,
        context: RequestContext,
        health_check_id: HealthCheckId,
        health_check_version: HealthCheckVersion = None,
        ip_address: IPAddress = None,
        port: Port = None,
        resource_path: ResourcePath = None,
        fully_qualified_domain_name: FullyQualifiedDomainName = None,
        search_string: SearchString = None,
        failure_threshold: FailureThreshold = None,
        inverted: Inverted = None,
        disabled: Disabled = None,
        health_threshold: HealthThreshold = None,
        child_health_checks: ChildHealthCheckList = None,
        enable_sni: EnableSNI = None,
        regions: HealthCheckRegionList = None,
        alarm_identifier: AlarmIdentifier = None,
        insufficient_data_health_status: InsufficientDataHealthStatus = None,
        reset_elements: ResettableElementNameList = None,
    ) -> UpdateHealthCheckResponse:
        raise NotImplementedError

    @handler("UpdateHostedZoneComment")
    def update_hosted_zone_comment(
        self, context: RequestContext, id: ResourceId, comment: ResourceDescription = None
    ) -> UpdateHostedZoneCommentResponse:
        raise NotImplementedError

    @handler("UpdateTrafficPolicyComment")
    def update_traffic_policy_comment(
        self,
        context: RequestContext,
        id: TrafficPolicyId,
        version: TrafficPolicyVersion,
        comment: TrafficPolicyComment,
    ) -> UpdateTrafficPolicyCommentResponse:
        raise NotImplementedError

    @handler("UpdateTrafficPolicyInstance")
    def update_traffic_policy_instance(
        self,
        context: RequestContext,
        id: TrafficPolicyInstanceId,
        ttl: TTL,
        traffic_policy_id: TrafficPolicyId,
        traffic_policy_version: TrafficPolicyVersion,
    ) -> UpdateTrafficPolicyInstanceResponse:
        raise NotImplementedError
