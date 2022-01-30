import sys
from datetime import datetime
from typing import Dict, List, Optional

if sys.version_info >= (3, 8):
    from typing import TypedDict
else:
    from typing_extensions import TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

ActionOrder = int
AllocationId = str
AlpnPolicyValue = str
AuthenticateCognitoActionAuthenticationRequestParamName = str
AuthenticateCognitoActionAuthenticationRequestParamValue = str
AuthenticateCognitoActionScope = str
AuthenticateCognitoActionSessionCookieName = str
AuthenticateCognitoActionUserPoolArn = str
AuthenticateCognitoActionUserPoolClientId = str
AuthenticateCognitoActionUserPoolDomain = str
AuthenticateOidcActionAuthenticationRequestParamName = str
AuthenticateOidcActionAuthenticationRequestParamValue = str
AuthenticateOidcActionAuthorizationEndpoint = str
AuthenticateOidcActionClientId = str
AuthenticateOidcActionClientSecret = str
AuthenticateOidcActionIssuer = str
AuthenticateOidcActionScope = str
AuthenticateOidcActionSessionCookieName = str
AuthenticateOidcActionTokenEndpoint = str
AuthenticateOidcActionUseExistingClientSecret = bool
AuthenticateOidcActionUserInfoEndpoint = str
CanonicalHostedZoneId = str
CertificateArn = str
CipherName = str
CipherPriority = int
ConditionFieldName = str
CustomerOwnedIpv4Pool = str
DNSName = str
Default = bool
Description = str
FixedResponseActionContentType = str
FixedResponseActionMessage = str
FixedResponseActionStatusCode = str
GrpcCode = str
HealthCheckEnabled = bool
HealthCheckIntervalSeconds = int
HealthCheckPort = str
HealthCheckThresholdCount = int
HealthCheckTimeoutSeconds = int
HttpCode = str
HttpHeaderConditionName = str
IPv6Address = str
IpAddress = str
IsDefault = bool
ListenerArn = str
LoadBalancerArn = str
LoadBalancerAttributeKey = str
LoadBalancerAttributeValue = str
LoadBalancerName = str
Marker = str
Max = str
Name = str
OutpostId = str
PageSize = int
Path = str
Port = int
PrivateIPv4Address = str
ProtocolVersion = str
RedirectActionHost = str
RedirectActionPath = str
RedirectActionPort = str
RedirectActionProtocol = str
RedirectActionQuery = str
ResourceArn = str
RuleArn = str
RulePriority = int
SecurityGroupId = str
SslPolicyName = str
SslProtocol = str
StateReason = str
String = str
StringValue = str
SubnetId = str
TagKey = str
TagValue = str
TargetGroupArn = str
TargetGroupAttributeKey = str
TargetGroupAttributeValue = str
TargetGroupName = str
TargetGroupStickinessDurationSeconds = int
TargetGroupStickinessEnabled = bool
TargetGroupWeight = int
TargetId = str
VpcId = str
ZoneName = str


class ActionTypeEnum(str):
    forward = "forward"
    authenticate_oidc = "authenticate-oidc"
    authenticate_cognito = "authenticate-cognito"
    redirect = "redirect"
    fixed_response = "fixed-response"


class AuthenticateCognitoActionConditionalBehaviorEnum(str):
    deny = "deny"
    allow = "allow"
    authenticate = "authenticate"


class AuthenticateOidcActionConditionalBehaviorEnum(str):
    deny = "deny"
    allow = "allow"
    authenticate = "authenticate"


class IpAddressType(str):
    ipv4 = "ipv4"
    dualstack = "dualstack"


class LoadBalancerSchemeEnum(str):
    internet_facing = "internet-facing"
    internal = "internal"


class LoadBalancerStateEnum(str):
    active = "active"
    provisioning = "provisioning"
    active_impaired = "active_impaired"
    failed = "failed"


class LoadBalancerTypeEnum(str):
    application = "application"
    network = "network"
    gateway = "gateway"


class ProtocolEnum(str):
    HTTP = "HTTP"
    HTTPS = "HTTPS"
    TCP = "TCP"
    TLS = "TLS"
    UDP = "UDP"
    TCP_UDP = "TCP_UDP"
    GENEVE = "GENEVE"


class RedirectActionStatusCodeEnum(str):
    HTTP_301 = "HTTP_301"
    HTTP_302 = "HTTP_302"


class TargetGroupIpAddressTypeEnum(str):
    ipv4 = "ipv4"
    ipv6 = "ipv6"


class TargetHealthReasonEnum(str):
    Elb_RegistrationInProgress = "Elb.RegistrationInProgress"
    Elb_InitialHealthChecking = "Elb.InitialHealthChecking"
    Target_ResponseCodeMismatch = "Target.ResponseCodeMismatch"
    Target_Timeout = "Target.Timeout"
    Target_FailedHealthChecks = "Target.FailedHealthChecks"
    Target_NotRegistered = "Target.NotRegistered"
    Target_NotInUse = "Target.NotInUse"
    Target_DeregistrationInProgress = "Target.DeregistrationInProgress"
    Target_InvalidState = "Target.InvalidState"
    Target_IpUnusable = "Target.IpUnusable"
    Target_HealthCheckDisabled = "Target.HealthCheckDisabled"
    Elb_InternalError = "Elb.InternalError"


class TargetHealthStateEnum(str):
    initial = "initial"
    healthy = "healthy"
    unhealthy = "unhealthy"
    unused = "unused"
    draining = "draining"
    unavailable = "unavailable"


class TargetTypeEnum(str):
    instance = "instance"
    ip = "ip"
    lambda_ = "lambda"
    alb = "alb"


class ALPNPolicyNotSupportedException(ServiceException):
    pass


class AllocationIdNotFoundException(ServiceException):
    pass


class AvailabilityZoneNotSupportedException(ServiceException):
    pass


class CertificateNotFoundException(ServiceException):
    pass


class DuplicateListenerException(ServiceException):
    pass


class DuplicateLoadBalancerNameException(ServiceException):
    pass


class DuplicateTagKeysException(ServiceException):
    pass


class DuplicateTargetGroupNameException(ServiceException):
    pass


class HealthUnavailableException(ServiceException):
    pass


class IncompatibleProtocolsException(ServiceException):
    pass


class InvalidConfigurationRequestException(ServiceException):
    pass


class InvalidLoadBalancerActionException(ServiceException):
    pass


class InvalidSchemeException(ServiceException):
    pass


class InvalidSecurityGroupException(ServiceException):
    pass


class InvalidSubnetException(ServiceException):
    pass


class InvalidTargetException(ServiceException):
    pass


class ListenerNotFoundException(ServiceException):
    pass


class LoadBalancerNotFoundException(ServiceException):
    pass


class OperationNotPermittedException(ServiceException):
    pass


class PriorityInUseException(ServiceException):
    pass


class ResourceInUseException(ServiceException):
    pass


class RuleNotFoundException(ServiceException):
    pass


class SSLPolicyNotFoundException(ServiceException):
    pass


class SubnetNotFoundException(ServiceException):
    pass


class TargetGroupAssociationLimitException(ServiceException):
    pass


class TargetGroupNotFoundException(ServiceException):
    pass


class TooManyActionsException(ServiceException):
    pass


class TooManyCertificatesException(ServiceException):
    pass


class TooManyListenersException(ServiceException):
    pass


class TooManyLoadBalancersException(ServiceException):
    pass


class TooManyRegistrationsForTargetIdException(ServiceException):
    pass


class TooManyRulesException(ServiceException):
    pass


class TooManyTagsException(ServiceException):
    pass


class TooManyTargetGroupsException(ServiceException):
    pass


class TooManyTargetsException(ServiceException):
    pass


class TooManyUniqueTargetGroupsPerLoadBalancerException(ServiceException):
    pass


class UnsupportedProtocolException(ServiceException):
    pass


class TargetGroupStickinessConfig(TypedDict, total=False):
    Enabled: Optional[TargetGroupStickinessEnabled]
    DurationSeconds: Optional[TargetGroupStickinessDurationSeconds]


class TargetGroupTuple(TypedDict, total=False):
    TargetGroupArn: Optional[TargetGroupArn]
    Weight: Optional[TargetGroupWeight]


TargetGroupList = List[TargetGroupTuple]


class ForwardActionConfig(TypedDict, total=False):
    TargetGroups: Optional[TargetGroupList]
    TargetGroupStickinessConfig: Optional[TargetGroupStickinessConfig]


class FixedResponseActionConfig(TypedDict, total=False):
    MessageBody: Optional[FixedResponseActionMessage]
    StatusCode: FixedResponseActionStatusCode
    ContentType: Optional[FixedResponseActionContentType]


class RedirectActionConfig(TypedDict, total=False):
    Protocol: Optional[RedirectActionProtocol]
    Port: Optional[RedirectActionPort]
    Host: Optional[RedirectActionHost]
    Path: Optional[RedirectActionPath]
    Query: Optional[RedirectActionQuery]
    StatusCode: RedirectActionStatusCodeEnum


AuthenticateCognitoActionAuthenticationRequestExtraParams = Dict[
    AuthenticateCognitoActionAuthenticationRequestParamName,
    AuthenticateCognitoActionAuthenticationRequestParamValue,
]
AuthenticateCognitoActionSessionTimeout = int


class AuthenticateCognitoActionConfig(TypedDict, total=False):
    UserPoolArn: AuthenticateCognitoActionUserPoolArn
    UserPoolClientId: AuthenticateCognitoActionUserPoolClientId
    UserPoolDomain: AuthenticateCognitoActionUserPoolDomain
    SessionCookieName: Optional[AuthenticateCognitoActionSessionCookieName]
    Scope: Optional[AuthenticateCognitoActionScope]
    SessionTimeout: Optional[AuthenticateCognitoActionSessionTimeout]
    AuthenticationRequestExtraParams: Optional[
        AuthenticateCognitoActionAuthenticationRequestExtraParams
    ]
    OnUnauthenticatedRequest: Optional[AuthenticateCognitoActionConditionalBehaviorEnum]


AuthenticateOidcActionAuthenticationRequestExtraParams = Dict[
    AuthenticateOidcActionAuthenticationRequestParamName,
    AuthenticateOidcActionAuthenticationRequestParamValue,
]
AuthenticateOidcActionSessionTimeout = int


class AuthenticateOidcActionConfig(TypedDict, total=False):
    Issuer: AuthenticateOidcActionIssuer
    AuthorizationEndpoint: AuthenticateOidcActionAuthorizationEndpoint
    TokenEndpoint: AuthenticateOidcActionTokenEndpoint
    UserInfoEndpoint: AuthenticateOidcActionUserInfoEndpoint
    ClientId: AuthenticateOidcActionClientId
    ClientSecret: Optional[AuthenticateOidcActionClientSecret]
    SessionCookieName: Optional[AuthenticateOidcActionSessionCookieName]
    Scope: Optional[AuthenticateOidcActionScope]
    SessionTimeout: Optional[AuthenticateOidcActionSessionTimeout]
    AuthenticationRequestExtraParams: Optional[
        AuthenticateOidcActionAuthenticationRequestExtraParams
    ]
    OnUnauthenticatedRequest: Optional[AuthenticateOidcActionConditionalBehaviorEnum]
    UseExistingClientSecret: Optional[AuthenticateOidcActionUseExistingClientSecret]


class Action(TypedDict, total=False):
    Type: ActionTypeEnum
    TargetGroupArn: Optional[TargetGroupArn]
    AuthenticateOidcConfig: Optional[AuthenticateOidcActionConfig]
    AuthenticateCognitoConfig: Optional[AuthenticateCognitoActionConfig]
    Order: Optional[ActionOrder]
    RedirectConfig: Optional[RedirectActionConfig]
    FixedResponseConfig: Optional[FixedResponseActionConfig]
    ForwardConfig: Optional[ForwardActionConfig]


Actions = List[Action]


class Certificate(TypedDict, total=False):
    CertificateArn: Optional[CertificateArn]
    IsDefault: Optional[Default]


CertificateList = List[Certificate]


class AddListenerCertificatesInput(ServiceRequest):
    ListenerArn: ListenerArn
    Certificates: CertificateList


class AddListenerCertificatesOutput(TypedDict, total=False):
    Certificates: Optional[CertificateList]


class Tag(TypedDict, total=False):
    Key: TagKey
    Value: Optional[TagValue]


TagList = List[Tag]
ResourceArns = List[ResourceArn]


class AddTagsInput(ServiceRequest):
    ResourceArns: ResourceArns
    Tags: TagList


class AddTagsOutput(TypedDict, total=False):
    pass


AlpnPolicyName = List[AlpnPolicyValue]


class LoadBalancerAddress(TypedDict, total=False):
    IpAddress: Optional[IpAddress]
    AllocationId: Optional[AllocationId]
    PrivateIPv4Address: Optional[PrivateIPv4Address]
    IPv6Address: Optional[IPv6Address]


LoadBalancerAddresses = List[LoadBalancerAddress]


class AvailabilityZone(TypedDict, total=False):
    ZoneName: Optional[ZoneName]
    SubnetId: Optional[SubnetId]
    OutpostId: Optional[OutpostId]
    LoadBalancerAddresses: Optional[LoadBalancerAddresses]


AvailabilityZones = List[AvailabilityZone]


class Cipher(TypedDict, total=False):
    Name: Optional[CipherName]
    Priority: Optional[CipherPriority]


Ciphers = List[Cipher]


class CreateListenerInput(ServiceRequest):
    LoadBalancerArn: LoadBalancerArn
    Protocol: Optional[ProtocolEnum]
    Port: Optional[Port]
    SslPolicy: Optional[SslPolicyName]
    Certificates: Optional[CertificateList]
    DefaultActions: Actions
    AlpnPolicy: Optional[AlpnPolicyName]
    Tags: Optional[TagList]


class Listener(TypedDict, total=False):
    ListenerArn: Optional[ListenerArn]
    LoadBalancerArn: Optional[LoadBalancerArn]
    Port: Optional[Port]
    Protocol: Optional[ProtocolEnum]
    Certificates: Optional[CertificateList]
    SslPolicy: Optional[SslPolicyName]
    DefaultActions: Optional[Actions]
    AlpnPolicy: Optional[AlpnPolicyName]


Listeners = List[Listener]


class CreateListenerOutput(TypedDict, total=False):
    Listeners: Optional[Listeners]


SecurityGroups = List[SecurityGroupId]


class SubnetMapping(TypedDict, total=False):
    SubnetId: Optional[SubnetId]
    AllocationId: Optional[AllocationId]
    PrivateIPv4Address: Optional[PrivateIPv4Address]
    IPv6Address: Optional[IPv6Address]


SubnetMappings = List[SubnetMapping]
Subnets = List[SubnetId]


class CreateLoadBalancerInput(ServiceRequest):
    Name: LoadBalancerName
    Subnets: Optional[Subnets]
    SubnetMappings: Optional[SubnetMappings]
    SecurityGroups: Optional[SecurityGroups]
    Scheme: Optional[LoadBalancerSchemeEnum]
    Tags: Optional[TagList]
    Type: Optional[LoadBalancerTypeEnum]
    IpAddressType: Optional[IpAddressType]
    CustomerOwnedIpv4Pool: Optional[CustomerOwnedIpv4Pool]


class LoadBalancerState(TypedDict, total=False):
    Code: Optional[LoadBalancerStateEnum]
    Reason: Optional[StateReason]


CreatedTime = datetime


class LoadBalancer(TypedDict, total=False):
    LoadBalancerArn: Optional[LoadBalancerArn]
    DNSName: Optional[DNSName]
    CanonicalHostedZoneId: Optional[CanonicalHostedZoneId]
    CreatedTime: Optional[CreatedTime]
    LoadBalancerName: Optional[LoadBalancerName]
    Scheme: Optional[LoadBalancerSchemeEnum]
    VpcId: Optional[VpcId]
    State: Optional[LoadBalancerState]
    Type: Optional[LoadBalancerTypeEnum]
    AvailabilityZones: Optional[AvailabilityZones]
    SecurityGroups: Optional[SecurityGroups]
    IpAddressType: Optional[IpAddressType]
    CustomerOwnedIpv4Pool: Optional[CustomerOwnedIpv4Pool]


LoadBalancers = List[LoadBalancer]


class CreateLoadBalancerOutput(TypedDict, total=False):
    LoadBalancers: Optional[LoadBalancers]


ListOfString = List[StringValue]


class SourceIpConditionConfig(TypedDict, total=False):
    Values: Optional[ListOfString]


class HttpRequestMethodConditionConfig(TypedDict, total=False):
    Values: Optional[ListOfString]


class QueryStringKeyValuePair(TypedDict, total=False):
    Key: Optional[StringValue]
    Value: Optional[StringValue]


QueryStringKeyValuePairList = List[QueryStringKeyValuePair]


class QueryStringConditionConfig(TypedDict, total=False):
    Values: Optional[QueryStringKeyValuePairList]


class HttpHeaderConditionConfig(TypedDict, total=False):
    HttpHeaderName: Optional[HttpHeaderConditionName]
    Values: Optional[ListOfString]


class PathPatternConditionConfig(TypedDict, total=False):
    Values: Optional[ListOfString]


class HostHeaderConditionConfig(TypedDict, total=False):
    Values: Optional[ListOfString]


class RuleCondition(TypedDict, total=False):
    Field: Optional[ConditionFieldName]
    Values: Optional[ListOfString]
    HostHeaderConfig: Optional[HostHeaderConditionConfig]
    PathPatternConfig: Optional[PathPatternConditionConfig]
    HttpHeaderConfig: Optional[HttpHeaderConditionConfig]
    QueryStringConfig: Optional[QueryStringConditionConfig]
    HttpRequestMethodConfig: Optional[HttpRequestMethodConditionConfig]
    SourceIpConfig: Optional[SourceIpConditionConfig]


RuleConditionList = List[RuleCondition]


class CreateRuleInput(ServiceRequest):
    ListenerArn: ListenerArn
    Conditions: RuleConditionList
    Priority: RulePriority
    Actions: Actions
    Tags: Optional[TagList]


class Rule(TypedDict, total=False):
    RuleArn: Optional[RuleArn]
    Priority: Optional[String]
    Conditions: Optional[RuleConditionList]
    Actions: Optional[Actions]
    IsDefault: Optional[IsDefault]


Rules = List[Rule]


class CreateRuleOutput(TypedDict, total=False):
    Rules: Optional[Rules]


class Matcher(TypedDict, total=False):
    HttpCode: Optional[HttpCode]
    GrpcCode: Optional[GrpcCode]


class CreateTargetGroupInput(ServiceRequest):
    Name: TargetGroupName
    Protocol: Optional[ProtocolEnum]
    ProtocolVersion: Optional[ProtocolVersion]
    Port: Optional[Port]
    VpcId: Optional[VpcId]
    HealthCheckProtocol: Optional[ProtocolEnum]
    HealthCheckPort: Optional[HealthCheckPort]
    HealthCheckEnabled: Optional[HealthCheckEnabled]
    HealthCheckPath: Optional[Path]
    HealthCheckIntervalSeconds: Optional[HealthCheckIntervalSeconds]
    HealthCheckTimeoutSeconds: Optional[HealthCheckTimeoutSeconds]
    HealthyThresholdCount: Optional[HealthCheckThresholdCount]
    UnhealthyThresholdCount: Optional[HealthCheckThresholdCount]
    Matcher: Optional[Matcher]
    TargetType: Optional[TargetTypeEnum]
    Tags: Optional[TagList]
    IpAddressType: Optional[TargetGroupIpAddressTypeEnum]


LoadBalancerArns = List[LoadBalancerArn]


class TargetGroup(TypedDict, total=False):
    TargetGroupArn: Optional[TargetGroupArn]
    TargetGroupName: Optional[TargetGroupName]
    Protocol: Optional[ProtocolEnum]
    Port: Optional[Port]
    VpcId: Optional[VpcId]
    HealthCheckProtocol: Optional[ProtocolEnum]
    HealthCheckPort: Optional[HealthCheckPort]
    HealthCheckEnabled: Optional[HealthCheckEnabled]
    HealthCheckIntervalSeconds: Optional[HealthCheckIntervalSeconds]
    HealthCheckTimeoutSeconds: Optional[HealthCheckTimeoutSeconds]
    HealthyThresholdCount: Optional[HealthCheckThresholdCount]
    UnhealthyThresholdCount: Optional[HealthCheckThresholdCount]
    HealthCheckPath: Optional[Path]
    Matcher: Optional[Matcher]
    LoadBalancerArns: Optional[LoadBalancerArns]
    TargetType: Optional[TargetTypeEnum]
    ProtocolVersion: Optional[ProtocolVersion]
    IpAddressType: Optional[TargetGroupIpAddressTypeEnum]


TargetGroups = List[TargetGroup]


class CreateTargetGroupOutput(TypedDict, total=False):
    TargetGroups: Optional[TargetGroups]


class DeleteListenerInput(ServiceRequest):
    ListenerArn: ListenerArn


class DeleteListenerOutput(TypedDict, total=False):
    pass


class DeleteLoadBalancerInput(ServiceRequest):
    LoadBalancerArn: LoadBalancerArn


class DeleteLoadBalancerOutput(TypedDict, total=False):
    pass


class DeleteRuleInput(ServiceRequest):
    RuleArn: RuleArn


class DeleteRuleOutput(TypedDict, total=False):
    pass


class DeleteTargetGroupInput(ServiceRequest):
    TargetGroupArn: TargetGroupArn


class DeleteTargetGroupOutput(TypedDict, total=False):
    pass


class TargetDescription(TypedDict, total=False):
    Id: TargetId
    Port: Optional[Port]
    AvailabilityZone: Optional[ZoneName]


TargetDescriptions = List[TargetDescription]


class DeregisterTargetsInput(ServiceRequest):
    TargetGroupArn: TargetGroupArn
    Targets: TargetDescriptions


class DeregisterTargetsOutput(TypedDict, total=False):
    pass


class DescribeAccountLimitsInput(ServiceRequest):
    Marker: Optional[Marker]
    PageSize: Optional[PageSize]


class Limit(TypedDict, total=False):
    Name: Optional[Name]
    Max: Optional[Max]


Limits = List[Limit]


class DescribeAccountLimitsOutput(TypedDict, total=False):
    Limits: Optional[Limits]
    NextMarker: Optional[Marker]


class DescribeListenerCertificatesInput(ServiceRequest):
    ListenerArn: ListenerArn
    Marker: Optional[Marker]
    PageSize: Optional[PageSize]


class DescribeListenerCertificatesOutput(TypedDict, total=False):
    Certificates: Optional[CertificateList]
    NextMarker: Optional[Marker]


ListenerArns = List[ListenerArn]


class DescribeListenersInput(ServiceRequest):
    LoadBalancerArn: Optional[LoadBalancerArn]
    ListenerArns: Optional[ListenerArns]
    Marker: Optional[Marker]
    PageSize: Optional[PageSize]


class DescribeListenersOutput(TypedDict, total=False):
    Listeners: Optional[Listeners]
    NextMarker: Optional[Marker]


class DescribeLoadBalancerAttributesInput(ServiceRequest):
    LoadBalancerArn: LoadBalancerArn


class LoadBalancerAttribute(TypedDict, total=False):
    Key: Optional[LoadBalancerAttributeKey]
    Value: Optional[LoadBalancerAttributeValue]


LoadBalancerAttributes = List[LoadBalancerAttribute]


class DescribeLoadBalancerAttributesOutput(TypedDict, total=False):
    Attributes: Optional[LoadBalancerAttributes]


LoadBalancerNames = List[LoadBalancerName]


class DescribeLoadBalancersInput(ServiceRequest):
    LoadBalancerArns: Optional[LoadBalancerArns]
    Names: Optional[LoadBalancerNames]
    Marker: Optional[Marker]
    PageSize: Optional[PageSize]


class DescribeLoadBalancersOutput(TypedDict, total=False):
    LoadBalancers: Optional[LoadBalancers]
    NextMarker: Optional[Marker]


RuleArns = List[RuleArn]


class DescribeRulesInput(ServiceRequest):
    ListenerArn: Optional[ListenerArn]
    RuleArns: Optional[RuleArns]
    Marker: Optional[Marker]
    PageSize: Optional[PageSize]


class DescribeRulesOutput(TypedDict, total=False):
    Rules: Optional[Rules]
    NextMarker: Optional[Marker]


SslPolicyNames = List[SslPolicyName]


class DescribeSSLPoliciesInput(ServiceRequest):
    Names: Optional[SslPolicyNames]
    Marker: Optional[Marker]
    PageSize: Optional[PageSize]
    LoadBalancerType: Optional[LoadBalancerTypeEnum]


SslProtocols = List[SslProtocol]


class SslPolicy(TypedDict, total=False):
    SslProtocols: Optional[SslProtocols]
    Ciphers: Optional[Ciphers]
    Name: Optional[SslPolicyName]
    SupportedLoadBalancerTypes: Optional[ListOfString]


SslPolicies = List[SslPolicy]


class DescribeSSLPoliciesOutput(TypedDict, total=False):
    SslPolicies: Optional[SslPolicies]
    NextMarker: Optional[Marker]


class DescribeTagsInput(ServiceRequest):
    ResourceArns: ResourceArns


class TagDescription(TypedDict, total=False):
    ResourceArn: Optional[ResourceArn]
    Tags: Optional[TagList]


TagDescriptions = List[TagDescription]


class DescribeTagsOutput(TypedDict, total=False):
    TagDescriptions: Optional[TagDescriptions]


class DescribeTargetGroupAttributesInput(ServiceRequest):
    TargetGroupArn: TargetGroupArn


class TargetGroupAttribute(TypedDict, total=False):
    Key: Optional[TargetGroupAttributeKey]
    Value: Optional[TargetGroupAttributeValue]


TargetGroupAttributes = List[TargetGroupAttribute]


class DescribeTargetGroupAttributesOutput(TypedDict, total=False):
    Attributes: Optional[TargetGroupAttributes]


TargetGroupNames = List[TargetGroupName]
TargetGroupArns = List[TargetGroupArn]


class DescribeTargetGroupsInput(ServiceRequest):
    LoadBalancerArn: Optional[LoadBalancerArn]
    TargetGroupArns: Optional[TargetGroupArns]
    Names: Optional[TargetGroupNames]
    Marker: Optional[Marker]
    PageSize: Optional[PageSize]


class DescribeTargetGroupsOutput(TypedDict, total=False):
    TargetGroups: Optional[TargetGroups]
    NextMarker: Optional[Marker]


class DescribeTargetHealthInput(ServiceRequest):
    TargetGroupArn: TargetGroupArn
    Targets: Optional[TargetDescriptions]


class TargetHealth(TypedDict, total=False):
    State: Optional[TargetHealthStateEnum]
    Reason: Optional[TargetHealthReasonEnum]
    Description: Optional[Description]


class TargetHealthDescription(TypedDict, total=False):
    Target: Optional[TargetDescription]
    HealthCheckPort: Optional[HealthCheckPort]
    TargetHealth: Optional[TargetHealth]


TargetHealthDescriptions = List[TargetHealthDescription]


class DescribeTargetHealthOutput(TypedDict, total=False):
    TargetHealthDescriptions: Optional[TargetHealthDescriptions]


class ModifyListenerInput(ServiceRequest):
    ListenerArn: ListenerArn
    Port: Optional[Port]
    Protocol: Optional[ProtocolEnum]
    SslPolicy: Optional[SslPolicyName]
    Certificates: Optional[CertificateList]
    DefaultActions: Optional[Actions]
    AlpnPolicy: Optional[AlpnPolicyName]


class ModifyListenerOutput(TypedDict, total=False):
    Listeners: Optional[Listeners]


class ModifyLoadBalancerAttributesInput(ServiceRequest):
    LoadBalancerArn: LoadBalancerArn
    Attributes: LoadBalancerAttributes


class ModifyLoadBalancerAttributesOutput(TypedDict, total=False):
    Attributes: Optional[LoadBalancerAttributes]


class ModifyRuleInput(ServiceRequest):
    RuleArn: RuleArn
    Conditions: Optional[RuleConditionList]
    Actions: Optional[Actions]


class ModifyRuleOutput(TypedDict, total=False):
    Rules: Optional[Rules]


class ModifyTargetGroupAttributesInput(ServiceRequest):
    TargetGroupArn: TargetGroupArn
    Attributes: TargetGroupAttributes


class ModifyTargetGroupAttributesOutput(TypedDict, total=False):
    Attributes: Optional[TargetGroupAttributes]


class ModifyTargetGroupInput(ServiceRequest):
    TargetGroupArn: TargetGroupArn
    HealthCheckProtocol: Optional[ProtocolEnum]
    HealthCheckPort: Optional[HealthCheckPort]
    HealthCheckPath: Optional[Path]
    HealthCheckEnabled: Optional[HealthCheckEnabled]
    HealthCheckIntervalSeconds: Optional[HealthCheckIntervalSeconds]
    HealthCheckTimeoutSeconds: Optional[HealthCheckTimeoutSeconds]
    HealthyThresholdCount: Optional[HealthCheckThresholdCount]
    UnhealthyThresholdCount: Optional[HealthCheckThresholdCount]
    Matcher: Optional[Matcher]


class ModifyTargetGroupOutput(TypedDict, total=False):
    TargetGroups: Optional[TargetGroups]


class RegisterTargetsInput(ServiceRequest):
    TargetGroupArn: TargetGroupArn
    Targets: TargetDescriptions


class RegisterTargetsOutput(TypedDict, total=False):
    pass


class RemoveListenerCertificatesInput(ServiceRequest):
    ListenerArn: ListenerArn
    Certificates: CertificateList


class RemoveListenerCertificatesOutput(TypedDict, total=False):
    pass


TagKeys = List[TagKey]


class RemoveTagsInput(ServiceRequest):
    ResourceArns: ResourceArns
    TagKeys: TagKeys


class RemoveTagsOutput(TypedDict, total=False):
    pass


class RulePriorityPair(TypedDict, total=False):
    RuleArn: Optional[RuleArn]
    Priority: Optional[RulePriority]


RulePriorityList = List[RulePriorityPair]


class SetIpAddressTypeInput(ServiceRequest):
    LoadBalancerArn: LoadBalancerArn
    IpAddressType: IpAddressType


class SetIpAddressTypeOutput(TypedDict, total=False):
    IpAddressType: Optional[IpAddressType]


class SetRulePrioritiesInput(ServiceRequest):
    RulePriorities: RulePriorityList


class SetRulePrioritiesOutput(TypedDict, total=False):
    Rules: Optional[Rules]


class SetSecurityGroupsInput(ServiceRequest):
    LoadBalancerArn: LoadBalancerArn
    SecurityGroups: SecurityGroups


class SetSecurityGroupsOutput(TypedDict, total=False):
    SecurityGroupIds: Optional[SecurityGroups]


class SetSubnetsInput(ServiceRequest):
    LoadBalancerArn: LoadBalancerArn
    Subnets: Optional[Subnets]
    SubnetMappings: Optional[SubnetMappings]
    IpAddressType: Optional[IpAddressType]


class SetSubnetsOutput(TypedDict, total=False):
    AvailabilityZones: Optional[AvailabilityZones]
    IpAddressType: Optional[IpAddressType]


class Elbv2Api:

    service = "elbv2"
    version = "2015-12-01"

    @handler("AddListenerCertificates")
    def add_listener_certificates(
        self, context: RequestContext, listener_arn: ListenerArn, certificates: CertificateList
    ) -> AddListenerCertificatesOutput:
        raise NotImplementedError

    @handler("AddTags")
    def add_tags(
        self, context: RequestContext, resource_arns: ResourceArns, tags: TagList
    ) -> AddTagsOutput:
        raise NotImplementedError

    @handler("CreateListener")
    def create_listener(
        self,
        context: RequestContext,
        load_balancer_arn: LoadBalancerArn,
        default_actions: Actions,
        protocol: ProtocolEnum = None,
        port: Port = None,
        ssl_policy: SslPolicyName = None,
        certificates: CertificateList = None,
        alpn_policy: AlpnPolicyName = None,
        tags: TagList = None,
    ) -> CreateListenerOutput:
        raise NotImplementedError

    @handler("CreateLoadBalancer", expand=False)
    def create_load_balancer(
        self, context: RequestContext, request: CreateLoadBalancerInput
    ) -> CreateLoadBalancerOutput:
        raise NotImplementedError

    @handler("CreateRule")
    def create_rule(
        self,
        context: RequestContext,
        listener_arn: ListenerArn,
        conditions: RuleConditionList,
        priority: RulePriority,
        actions: Actions,
        tags: TagList = None,
    ) -> CreateRuleOutput:
        raise NotImplementedError

    @handler("CreateTargetGroup")
    def create_target_group(
        self,
        context: RequestContext,
        name: TargetGroupName,
        protocol: ProtocolEnum = None,
        protocol_version: ProtocolVersion = None,
        port: Port = None,
        vpc_id: VpcId = None,
        health_check_protocol: ProtocolEnum = None,
        health_check_port: HealthCheckPort = None,
        health_check_enabled: HealthCheckEnabled = None,
        health_check_path: Path = None,
        health_check_interval_seconds: HealthCheckIntervalSeconds = None,
        health_check_timeout_seconds: HealthCheckTimeoutSeconds = None,
        healthy_threshold_count: HealthCheckThresholdCount = None,
        unhealthy_threshold_count: HealthCheckThresholdCount = None,
        matcher: Matcher = None,
        target_type: TargetTypeEnum = None,
        tags: TagList = None,
        ip_address_type: TargetGroupIpAddressTypeEnum = None,
    ) -> CreateTargetGroupOutput:
        raise NotImplementedError

    @handler("DeleteListener")
    def delete_listener(
        self, context: RequestContext, listener_arn: ListenerArn
    ) -> DeleteListenerOutput:
        raise NotImplementedError

    @handler("DeleteLoadBalancer")
    def delete_load_balancer(
        self, context: RequestContext, load_balancer_arn: LoadBalancerArn
    ) -> DeleteLoadBalancerOutput:
        raise NotImplementedError

    @handler("DeleteRule")
    def delete_rule(self, context: RequestContext, rule_arn: RuleArn) -> DeleteRuleOutput:
        raise NotImplementedError

    @handler("DeleteTargetGroup")
    def delete_target_group(
        self, context: RequestContext, target_group_arn: TargetGroupArn
    ) -> DeleteTargetGroupOutput:
        raise NotImplementedError

    @handler("DeregisterTargets")
    def deregister_targets(
        self, context: RequestContext, target_group_arn: TargetGroupArn, targets: TargetDescriptions
    ) -> DeregisterTargetsOutput:
        raise NotImplementedError

    @handler("DescribeAccountLimits")
    def describe_account_limits(
        self, context: RequestContext, marker: Marker = None, page_size: PageSize = None
    ) -> DescribeAccountLimitsOutput:
        raise NotImplementedError

    @handler("DescribeListenerCertificates")
    def describe_listener_certificates(
        self,
        context: RequestContext,
        listener_arn: ListenerArn,
        marker: Marker = None,
        page_size: PageSize = None,
    ) -> DescribeListenerCertificatesOutput:
        raise NotImplementedError

    @handler("DescribeListeners")
    def describe_listeners(
        self,
        context: RequestContext,
        load_balancer_arn: LoadBalancerArn = None,
        listener_arns: ListenerArns = None,
        marker: Marker = None,
        page_size: PageSize = None,
    ) -> DescribeListenersOutput:
        raise NotImplementedError

    @handler("DescribeLoadBalancerAttributes")
    def describe_load_balancer_attributes(
        self, context: RequestContext, load_balancer_arn: LoadBalancerArn
    ) -> DescribeLoadBalancerAttributesOutput:
        raise NotImplementedError

    @handler("DescribeLoadBalancers")
    def describe_load_balancers(
        self,
        context: RequestContext,
        load_balancer_arns: LoadBalancerArns = None,
        names: LoadBalancerNames = None,
        marker: Marker = None,
        page_size: PageSize = None,
    ) -> DescribeLoadBalancersOutput:
        raise NotImplementedError

    @handler("DescribeRules")
    def describe_rules(
        self,
        context: RequestContext,
        listener_arn: ListenerArn = None,
        rule_arns: RuleArns = None,
        marker: Marker = None,
        page_size: PageSize = None,
    ) -> DescribeRulesOutput:
        raise NotImplementedError

    @handler("DescribeSSLPolicies")
    def describe_ssl_policies(
        self,
        context: RequestContext,
        names: SslPolicyNames = None,
        marker: Marker = None,
        page_size: PageSize = None,
        load_balancer_type: LoadBalancerTypeEnum = None,
    ) -> DescribeSSLPoliciesOutput:
        raise NotImplementedError

    @handler("DescribeTags")
    def describe_tags(
        self, context: RequestContext, resource_arns: ResourceArns
    ) -> DescribeTagsOutput:
        raise NotImplementedError

    @handler("DescribeTargetGroupAttributes")
    def describe_target_group_attributes(
        self, context: RequestContext, target_group_arn: TargetGroupArn
    ) -> DescribeTargetGroupAttributesOutput:
        raise NotImplementedError

    @handler("DescribeTargetGroups")
    def describe_target_groups(
        self,
        context: RequestContext,
        load_balancer_arn: LoadBalancerArn = None,
        target_group_arns: TargetGroupArns = None,
        names: TargetGroupNames = None,
        marker: Marker = None,
        page_size: PageSize = None,
    ) -> DescribeTargetGroupsOutput:
        raise NotImplementedError

    @handler("DescribeTargetHealth")
    def describe_target_health(
        self,
        context: RequestContext,
        target_group_arn: TargetGroupArn,
        targets: TargetDescriptions = None,
    ) -> DescribeTargetHealthOutput:
        raise NotImplementedError

    @handler("ModifyListener")
    def modify_listener(
        self,
        context: RequestContext,
        listener_arn: ListenerArn,
        port: Port = None,
        protocol: ProtocolEnum = None,
        ssl_policy: SslPolicyName = None,
        certificates: CertificateList = None,
        default_actions: Actions = None,
        alpn_policy: AlpnPolicyName = None,
    ) -> ModifyListenerOutput:
        raise NotImplementedError

    @handler("ModifyLoadBalancerAttributes")
    def modify_load_balancer_attributes(
        self,
        context: RequestContext,
        load_balancer_arn: LoadBalancerArn,
        attributes: LoadBalancerAttributes,
    ) -> ModifyLoadBalancerAttributesOutput:
        raise NotImplementedError

    @handler("ModifyRule")
    def modify_rule(
        self,
        context: RequestContext,
        rule_arn: RuleArn,
        conditions: RuleConditionList = None,
        actions: Actions = None,
    ) -> ModifyRuleOutput:
        raise NotImplementedError

    @handler("ModifyTargetGroup")
    def modify_target_group(
        self,
        context: RequestContext,
        target_group_arn: TargetGroupArn,
        health_check_protocol: ProtocolEnum = None,
        health_check_port: HealthCheckPort = None,
        health_check_path: Path = None,
        health_check_enabled: HealthCheckEnabled = None,
        health_check_interval_seconds: HealthCheckIntervalSeconds = None,
        health_check_timeout_seconds: HealthCheckTimeoutSeconds = None,
        healthy_threshold_count: HealthCheckThresholdCount = None,
        unhealthy_threshold_count: HealthCheckThresholdCount = None,
        matcher: Matcher = None,
    ) -> ModifyTargetGroupOutput:
        raise NotImplementedError

    @handler("ModifyTargetGroupAttributes")
    def modify_target_group_attributes(
        self,
        context: RequestContext,
        target_group_arn: TargetGroupArn,
        attributes: TargetGroupAttributes,
    ) -> ModifyTargetGroupAttributesOutput:
        raise NotImplementedError

    @handler("RegisterTargets")
    def register_targets(
        self, context: RequestContext, target_group_arn: TargetGroupArn, targets: TargetDescriptions
    ) -> RegisterTargetsOutput:
        raise NotImplementedError

    @handler("RemoveListenerCertificates")
    def remove_listener_certificates(
        self, context: RequestContext, listener_arn: ListenerArn, certificates: CertificateList
    ) -> RemoveListenerCertificatesOutput:
        raise NotImplementedError

    @handler("RemoveTags")
    def remove_tags(
        self, context: RequestContext, resource_arns: ResourceArns, tag_keys: TagKeys
    ) -> RemoveTagsOutput:
        raise NotImplementedError

    @handler("SetIpAddressType")
    def set_ip_address_type(
        self,
        context: RequestContext,
        load_balancer_arn: LoadBalancerArn,
        ip_address_type: IpAddressType,
    ) -> SetIpAddressTypeOutput:
        raise NotImplementedError

    @handler("SetRulePriorities")
    def set_rule_priorities(
        self, context: RequestContext, rule_priorities: RulePriorityList
    ) -> SetRulePrioritiesOutput:
        raise NotImplementedError

    @handler("SetSecurityGroups")
    def set_security_groups(
        self,
        context: RequestContext,
        load_balancer_arn: LoadBalancerArn,
        security_groups: SecurityGroups,
    ) -> SetSecurityGroupsOutput:
        raise NotImplementedError

    @handler("SetSubnets")
    def set_subnets(
        self,
        context: RequestContext,
        load_balancer_arn: LoadBalancerArn,
        subnets: Subnets = None,
        subnet_mappings: SubnetMappings = None,
        ip_address_type: IpAddressType = None,
    ) -> SetSubnetsOutput:
        raise NotImplementedError
