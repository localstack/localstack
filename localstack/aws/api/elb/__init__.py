import sys
from datetime import datetime
from typing import List, Optional

if sys.version_info >= (3, 8):
    from typing import TypedDict
else:
    from typing_extensions import TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

AccessLogEnabled = bool
AccessLogInterval = int
AccessLogPrefix = str
AccessPointName = str
AccessPointPort = int
AdditionalAttributeKey = str
AdditionalAttributeValue = str
AttributeName = str
AttributeType = str
AttributeValue = str
AvailabilityZone = str
Cardinality = str
ConnectionDrainingEnabled = bool
ConnectionDrainingTimeout = int
CookieName = str
CrossZoneLoadBalancingEnabled = bool
DNSName = str
DefaultValue = str
Description = str
EndPointPort = int
HealthCheckInterval = int
HealthCheckTarget = str
HealthCheckTimeout = int
HealthyThreshold = int
IdleTimeout = int
InstanceId = str
InstancePort = int
LoadBalancerScheme = str
Marker = str
Max = str
Name = str
PageSize = int
PolicyName = str
PolicyTypeName = str
Protocol = str
ReasonCode = str
S3BucketName = str
SSLCertificateId = str
SecurityGroupId = str
SecurityGroupName = str
SecurityGroupOwnerAlias = str
State = str
SubnetId = str
TagKey = str
TagValue = str
UnhealthyThreshold = int
VPCId = str


class AccessPointNotFoundException(ServiceException):
    pass


class CertificateNotFoundException(ServiceException):
    pass


class DependencyThrottleException(ServiceException):
    pass


class DuplicateAccessPointNameException(ServiceException):
    pass


class DuplicateListenerException(ServiceException):
    pass


class DuplicatePolicyNameException(ServiceException):
    pass


class DuplicateTagKeysException(ServiceException):
    pass


class InvalidConfigurationRequestException(ServiceException):
    pass


class InvalidEndPointException(ServiceException):
    pass


class InvalidSchemeException(ServiceException):
    pass


class InvalidSecurityGroupException(ServiceException):
    pass


class InvalidSubnetException(ServiceException):
    pass


class ListenerNotFoundException(ServiceException):
    pass


class LoadBalancerAttributeNotFoundException(ServiceException):
    pass


class OperationNotPermittedException(ServiceException):
    pass


class PolicyNotFoundException(ServiceException):
    pass


class PolicyTypeNotFoundException(ServiceException):
    pass


class SubnetNotFoundException(ServiceException):
    pass


class TooManyAccessPointsException(ServiceException):
    pass


class TooManyPoliciesException(ServiceException):
    pass


class TooManyTagsException(ServiceException):
    pass


class UnsupportedProtocolException(ServiceException):
    pass


class AccessLog(TypedDict, total=False):
    Enabled: AccessLogEnabled
    S3BucketName: Optional[S3BucketName]
    EmitInterval: Optional[AccessLogInterval]
    S3BucketPrefix: Optional[AccessLogPrefix]


AvailabilityZones = List[AvailabilityZone]


class AddAvailabilityZonesInput(ServiceRequest):
    LoadBalancerName: AccessPointName
    AvailabilityZones: AvailabilityZones


class AddAvailabilityZonesOutput(TypedDict, total=False):
    AvailabilityZones: Optional[AvailabilityZones]


class Tag(TypedDict, total=False):
    Key: TagKey
    Value: Optional[TagValue]


TagList = List[Tag]
LoadBalancerNames = List[AccessPointName]


class AddTagsInput(ServiceRequest):
    LoadBalancerNames: LoadBalancerNames
    Tags: TagList


class AddTagsOutput(TypedDict, total=False):
    pass


class AdditionalAttribute(TypedDict, total=False):
    Key: Optional[AdditionalAttributeKey]
    Value: Optional[AdditionalAttributeValue]


AdditionalAttributes = List[AdditionalAttribute]


class AppCookieStickinessPolicy(TypedDict, total=False):
    PolicyName: Optional[PolicyName]
    CookieName: Optional[CookieName]


AppCookieStickinessPolicies = List[AppCookieStickinessPolicy]
SecurityGroups = List[SecurityGroupId]


class ApplySecurityGroupsToLoadBalancerInput(ServiceRequest):
    LoadBalancerName: AccessPointName
    SecurityGroups: SecurityGroups


class ApplySecurityGroupsToLoadBalancerOutput(TypedDict, total=False):
    SecurityGroups: Optional[SecurityGroups]


Subnets = List[SubnetId]


class AttachLoadBalancerToSubnetsInput(ServiceRequest):
    LoadBalancerName: AccessPointName
    Subnets: Subnets


class AttachLoadBalancerToSubnetsOutput(TypedDict, total=False):
    Subnets: Optional[Subnets]


PolicyNames = List[PolicyName]


class BackendServerDescription(TypedDict, total=False):
    InstancePort: Optional[InstancePort]
    PolicyNames: Optional[PolicyNames]


BackendServerDescriptions = List[BackendServerDescription]


class HealthCheck(TypedDict, total=False):
    Target: HealthCheckTarget
    Interval: HealthCheckInterval
    Timeout: HealthCheckTimeout
    UnhealthyThreshold: UnhealthyThreshold
    HealthyThreshold: HealthyThreshold


class ConfigureHealthCheckInput(ServiceRequest):
    LoadBalancerName: AccessPointName
    HealthCheck: HealthCheck


class ConfigureHealthCheckOutput(TypedDict, total=False):
    HealthCheck: Optional[HealthCheck]


class ConnectionDraining(TypedDict, total=False):
    Enabled: ConnectionDrainingEnabled
    Timeout: Optional[ConnectionDrainingTimeout]


class ConnectionSettings(TypedDict, total=False):
    IdleTimeout: IdleTimeout


CookieExpirationPeriod = int


class Listener(TypedDict, total=False):
    Protocol: Protocol
    LoadBalancerPort: AccessPointPort
    InstanceProtocol: Optional[Protocol]
    InstancePort: InstancePort
    SSLCertificateId: Optional[SSLCertificateId]


Listeners = List[Listener]


class CreateAccessPointInput(ServiceRequest):
    LoadBalancerName: AccessPointName
    Listeners: Listeners
    AvailabilityZones: Optional[AvailabilityZones]
    Subnets: Optional[Subnets]
    SecurityGroups: Optional[SecurityGroups]
    Scheme: Optional[LoadBalancerScheme]
    Tags: Optional[TagList]


class CreateAccessPointOutput(TypedDict, total=False):
    DNSName: Optional[DNSName]


class CreateAppCookieStickinessPolicyInput(ServiceRequest):
    LoadBalancerName: AccessPointName
    PolicyName: PolicyName
    CookieName: CookieName


class CreateAppCookieStickinessPolicyOutput(TypedDict, total=False):
    pass


class CreateLBCookieStickinessPolicyInput(ServiceRequest):
    LoadBalancerName: AccessPointName
    PolicyName: PolicyName
    CookieExpirationPeriod: Optional[CookieExpirationPeriod]


class CreateLBCookieStickinessPolicyOutput(TypedDict, total=False):
    pass


class CreateLoadBalancerListenerInput(ServiceRequest):
    LoadBalancerName: AccessPointName
    Listeners: Listeners


class CreateLoadBalancerListenerOutput(TypedDict, total=False):
    pass


class PolicyAttribute(TypedDict, total=False):
    AttributeName: Optional[AttributeName]
    AttributeValue: Optional[AttributeValue]


PolicyAttributes = List[PolicyAttribute]


class CreateLoadBalancerPolicyInput(ServiceRequest):
    LoadBalancerName: AccessPointName
    PolicyName: PolicyName
    PolicyTypeName: PolicyTypeName
    PolicyAttributes: Optional[PolicyAttributes]


class CreateLoadBalancerPolicyOutput(TypedDict, total=False):
    pass


CreatedTime = datetime


class CrossZoneLoadBalancing(TypedDict, total=False):
    Enabled: CrossZoneLoadBalancingEnabled


class DeleteAccessPointInput(ServiceRequest):
    LoadBalancerName: AccessPointName


class DeleteAccessPointOutput(TypedDict, total=False):
    pass


Ports = List[AccessPointPort]


class DeleteLoadBalancerListenerInput(ServiceRequest):
    LoadBalancerName: AccessPointName
    LoadBalancerPorts: Ports


class DeleteLoadBalancerListenerOutput(TypedDict, total=False):
    pass


class DeleteLoadBalancerPolicyInput(ServiceRequest):
    LoadBalancerName: AccessPointName
    PolicyName: PolicyName


class DeleteLoadBalancerPolicyOutput(TypedDict, total=False):
    pass


class Instance(TypedDict, total=False):
    InstanceId: Optional[InstanceId]


Instances = List[Instance]


class DeregisterEndPointsInput(ServiceRequest):
    LoadBalancerName: AccessPointName
    Instances: Instances


class DeregisterEndPointsOutput(TypedDict, total=False):
    Instances: Optional[Instances]


class DescribeAccessPointsInput(ServiceRequest):
    LoadBalancerNames: Optional[LoadBalancerNames]
    Marker: Optional[Marker]
    PageSize: Optional[PageSize]


class SourceSecurityGroup(TypedDict, total=False):
    OwnerAlias: Optional[SecurityGroupOwnerAlias]
    GroupName: Optional[SecurityGroupName]


class LBCookieStickinessPolicy(TypedDict, total=False):
    PolicyName: Optional[PolicyName]
    CookieExpirationPeriod: Optional[CookieExpirationPeriod]


LBCookieStickinessPolicies = List[LBCookieStickinessPolicy]


class Policies(TypedDict, total=False):
    AppCookieStickinessPolicies: Optional[AppCookieStickinessPolicies]
    LBCookieStickinessPolicies: Optional[LBCookieStickinessPolicies]
    OtherPolicies: Optional[PolicyNames]


class ListenerDescription(TypedDict, total=False):
    Listener: Optional[Listener]
    PolicyNames: Optional[PolicyNames]


ListenerDescriptions = List[ListenerDescription]


class LoadBalancerDescription(TypedDict, total=False):
    LoadBalancerName: Optional[AccessPointName]
    DNSName: Optional[DNSName]
    CanonicalHostedZoneName: Optional[DNSName]
    CanonicalHostedZoneNameID: Optional[DNSName]
    ListenerDescriptions: Optional[ListenerDescriptions]
    Policies: Optional[Policies]
    BackendServerDescriptions: Optional[BackendServerDescriptions]
    AvailabilityZones: Optional[AvailabilityZones]
    Subnets: Optional[Subnets]
    VPCId: Optional[VPCId]
    Instances: Optional[Instances]
    HealthCheck: Optional[HealthCheck]
    SourceSecurityGroup: Optional[SourceSecurityGroup]
    SecurityGroups: Optional[SecurityGroups]
    CreatedTime: Optional[CreatedTime]
    Scheme: Optional[LoadBalancerScheme]


LoadBalancerDescriptions = List[LoadBalancerDescription]


class DescribeAccessPointsOutput(TypedDict, total=False):
    LoadBalancerDescriptions: Optional[LoadBalancerDescriptions]
    NextMarker: Optional[Marker]


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


class DescribeEndPointStateInput(ServiceRequest):
    LoadBalancerName: AccessPointName
    Instances: Optional[Instances]


class InstanceState(TypedDict, total=False):
    InstanceId: Optional[InstanceId]
    State: Optional[State]
    ReasonCode: Optional[ReasonCode]
    Description: Optional[Description]


InstanceStates = List[InstanceState]


class DescribeEndPointStateOutput(TypedDict, total=False):
    InstanceStates: Optional[InstanceStates]


class DescribeLoadBalancerAttributesInput(ServiceRequest):
    LoadBalancerName: AccessPointName


class LoadBalancerAttributes(TypedDict, total=False):
    CrossZoneLoadBalancing: Optional[CrossZoneLoadBalancing]
    AccessLog: Optional[AccessLog]
    ConnectionDraining: Optional[ConnectionDraining]
    ConnectionSettings: Optional[ConnectionSettings]
    AdditionalAttributes: Optional[AdditionalAttributes]


class DescribeLoadBalancerAttributesOutput(TypedDict, total=False):
    LoadBalancerAttributes: Optional[LoadBalancerAttributes]


class DescribeLoadBalancerPoliciesInput(ServiceRequest):
    LoadBalancerName: Optional[AccessPointName]
    PolicyNames: Optional[PolicyNames]


class PolicyAttributeDescription(TypedDict, total=False):
    AttributeName: Optional[AttributeName]
    AttributeValue: Optional[AttributeValue]


PolicyAttributeDescriptions = List[PolicyAttributeDescription]


class PolicyDescription(TypedDict, total=False):
    PolicyName: Optional[PolicyName]
    PolicyTypeName: Optional[PolicyTypeName]
    PolicyAttributeDescriptions: Optional[PolicyAttributeDescriptions]


PolicyDescriptions = List[PolicyDescription]


class DescribeLoadBalancerPoliciesOutput(TypedDict, total=False):
    PolicyDescriptions: Optional[PolicyDescriptions]


PolicyTypeNames = List[PolicyTypeName]


class DescribeLoadBalancerPolicyTypesInput(ServiceRequest):
    PolicyTypeNames: Optional[PolicyTypeNames]


class PolicyAttributeTypeDescription(TypedDict, total=False):
    AttributeName: Optional[AttributeName]
    AttributeType: Optional[AttributeType]
    Description: Optional[Description]
    DefaultValue: Optional[DefaultValue]
    Cardinality: Optional[Cardinality]


PolicyAttributeTypeDescriptions = List[PolicyAttributeTypeDescription]


class PolicyTypeDescription(TypedDict, total=False):
    PolicyTypeName: Optional[PolicyTypeName]
    Description: Optional[Description]
    PolicyAttributeTypeDescriptions: Optional[PolicyAttributeTypeDescriptions]


PolicyTypeDescriptions = List[PolicyTypeDescription]


class DescribeLoadBalancerPolicyTypesOutput(TypedDict, total=False):
    PolicyTypeDescriptions: Optional[PolicyTypeDescriptions]


LoadBalancerNamesMax20 = List[AccessPointName]


class DescribeTagsInput(ServiceRequest):
    LoadBalancerNames: LoadBalancerNamesMax20


class TagDescription(TypedDict, total=False):
    LoadBalancerName: Optional[AccessPointName]
    Tags: Optional[TagList]


TagDescriptions = List[TagDescription]


class DescribeTagsOutput(TypedDict, total=False):
    TagDescriptions: Optional[TagDescriptions]


class DetachLoadBalancerFromSubnetsInput(ServiceRequest):
    LoadBalancerName: AccessPointName
    Subnets: Subnets


class DetachLoadBalancerFromSubnetsOutput(TypedDict, total=False):
    Subnets: Optional[Subnets]


class ModifyLoadBalancerAttributesInput(ServiceRequest):
    LoadBalancerName: AccessPointName
    LoadBalancerAttributes: LoadBalancerAttributes


class ModifyLoadBalancerAttributesOutput(TypedDict, total=False):
    LoadBalancerName: Optional[AccessPointName]
    LoadBalancerAttributes: Optional[LoadBalancerAttributes]


class RegisterEndPointsInput(ServiceRequest):
    LoadBalancerName: AccessPointName
    Instances: Instances


class RegisterEndPointsOutput(TypedDict, total=False):
    Instances: Optional[Instances]


class RemoveAvailabilityZonesInput(ServiceRequest):
    LoadBalancerName: AccessPointName
    AvailabilityZones: AvailabilityZones


class RemoveAvailabilityZonesOutput(TypedDict, total=False):
    AvailabilityZones: Optional[AvailabilityZones]


class TagKeyOnly(TypedDict, total=False):
    Key: Optional[TagKey]


TagKeyList = List[TagKeyOnly]


class RemoveTagsInput(ServiceRequest):
    LoadBalancerNames: LoadBalancerNames
    Tags: TagKeyList


class RemoveTagsOutput(TypedDict, total=False):
    pass


class SetLoadBalancerListenerSSLCertificateInput(ServiceRequest):
    LoadBalancerName: AccessPointName
    LoadBalancerPort: AccessPointPort
    SSLCertificateId: SSLCertificateId


class SetLoadBalancerListenerSSLCertificateOutput(TypedDict, total=False):
    pass


class SetLoadBalancerPoliciesForBackendServerInput(ServiceRequest):
    LoadBalancerName: AccessPointName
    InstancePort: EndPointPort
    PolicyNames: PolicyNames


class SetLoadBalancerPoliciesForBackendServerOutput(TypedDict, total=False):
    pass


class SetLoadBalancerPoliciesOfListenerInput(ServiceRequest):
    LoadBalancerName: AccessPointName
    LoadBalancerPort: AccessPointPort
    PolicyNames: PolicyNames


class SetLoadBalancerPoliciesOfListenerOutput(TypedDict, total=False):
    pass


class ElbApi:

    service = "elb"
    version = "2012-06-01"

    @handler("AddTags")
    def add_tags(
        self, context: RequestContext, load_balancer_names: LoadBalancerNames, tags: TagList
    ) -> AddTagsOutput:
        raise NotImplementedError

    @handler("ApplySecurityGroupsToLoadBalancer")
    def apply_security_groups_to_load_balancer(
        self,
        context: RequestContext,
        load_balancer_name: AccessPointName,
        security_groups: SecurityGroups,
    ) -> ApplySecurityGroupsToLoadBalancerOutput:
        raise NotImplementedError

    @handler("AttachLoadBalancerToSubnets")
    def attach_load_balancer_to_subnets(
        self, context: RequestContext, load_balancer_name: AccessPointName, subnets: Subnets
    ) -> AttachLoadBalancerToSubnetsOutput:
        raise NotImplementedError

    @handler("ConfigureHealthCheck")
    def configure_health_check(
        self,
        context: RequestContext,
        load_balancer_name: AccessPointName,
        health_check: HealthCheck,
    ) -> ConfigureHealthCheckOutput:
        raise NotImplementedError

    @handler("CreateAppCookieStickinessPolicy")
    def create_app_cookie_stickiness_policy(
        self,
        context: RequestContext,
        load_balancer_name: AccessPointName,
        policy_name: PolicyName,
        cookie_name: CookieName,
    ) -> CreateAppCookieStickinessPolicyOutput:
        raise NotImplementedError

    @handler("CreateLBCookieStickinessPolicy")
    def create_lb_cookie_stickiness_policy(
        self,
        context: RequestContext,
        load_balancer_name: AccessPointName,
        policy_name: PolicyName,
        cookie_expiration_period: CookieExpirationPeriod = None,
    ) -> CreateLBCookieStickinessPolicyOutput:
        raise NotImplementedError

    @handler("CreateLoadBalancer")
    def create_load_balancer(
        self,
        context: RequestContext,
        load_balancer_name: AccessPointName,
        listeners: Listeners,
        availability_zones: AvailabilityZones = None,
        subnets: Subnets = None,
        security_groups: SecurityGroups = None,
        scheme: LoadBalancerScheme = None,
        tags: TagList = None,
    ) -> CreateAccessPointOutput:
        raise NotImplementedError

    @handler("CreateLoadBalancerListeners")
    def create_load_balancer_listeners(
        self, context: RequestContext, load_balancer_name: AccessPointName, listeners: Listeners
    ) -> CreateLoadBalancerListenerOutput:
        raise NotImplementedError

    @handler("CreateLoadBalancerPolicy")
    def create_load_balancer_policy(
        self,
        context: RequestContext,
        load_balancer_name: AccessPointName,
        policy_name: PolicyName,
        policy_type_name: PolicyTypeName,
        policy_attributes: PolicyAttributes = None,
    ) -> CreateLoadBalancerPolicyOutput:
        raise NotImplementedError

    @handler("DeleteLoadBalancer")
    def delete_load_balancer(
        self, context: RequestContext, load_balancer_name: AccessPointName
    ) -> DeleteAccessPointOutput:
        raise NotImplementedError

    @handler("DeleteLoadBalancerListeners")
    def delete_load_balancer_listeners(
        self,
        context: RequestContext,
        load_balancer_name: AccessPointName,
        load_balancer_ports: Ports,
    ) -> DeleteLoadBalancerListenerOutput:
        raise NotImplementedError

    @handler("DeleteLoadBalancerPolicy")
    def delete_load_balancer_policy(
        self, context: RequestContext, load_balancer_name: AccessPointName, policy_name: PolicyName
    ) -> DeleteLoadBalancerPolicyOutput:
        raise NotImplementedError

    @handler("DeregisterInstancesFromLoadBalancer")
    def deregister_instances_from_load_balancer(
        self, context: RequestContext, load_balancer_name: AccessPointName, instances: Instances
    ) -> DeregisterEndPointsOutput:
        raise NotImplementedError

    @handler("DescribeAccountLimits")
    def describe_account_limits(
        self, context: RequestContext, marker: Marker = None, page_size: PageSize = None
    ) -> DescribeAccountLimitsOutput:
        raise NotImplementedError

    @handler("DescribeInstanceHealth")
    def describe_instance_health(
        self,
        context: RequestContext,
        load_balancer_name: AccessPointName,
        instances: Instances = None,
    ) -> DescribeEndPointStateOutput:
        raise NotImplementedError

    @handler("DescribeLoadBalancerAttributes")
    def describe_load_balancer_attributes(
        self, context: RequestContext, load_balancer_name: AccessPointName
    ) -> DescribeLoadBalancerAttributesOutput:
        raise NotImplementedError

    @handler("DescribeLoadBalancerPolicies")
    def describe_load_balancer_policies(
        self,
        context: RequestContext,
        load_balancer_name: AccessPointName = None,
        policy_names: PolicyNames = None,
    ) -> DescribeLoadBalancerPoliciesOutput:
        raise NotImplementedError

    @handler("DescribeLoadBalancerPolicyTypes")
    def describe_load_balancer_policy_types(
        self, context: RequestContext, policy_type_names: PolicyTypeNames = None
    ) -> DescribeLoadBalancerPolicyTypesOutput:
        raise NotImplementedError

    @handler("DescribeLoadBalancers")
    def describe_load_balancers(
        self,
        context: RequestContext,
        load_balancer_names: LoadBalancerNames = None,
        marker: Marker = None,
        page_size: PageSize = None,
    ) -> DescribeAccessPointsOutput:
        raise NotImplementedError

    @handler("DescribeTags")
    def describe_tags(
        self, context: RequestContext, load_balancer_names: LoadBalancerNamesMax20
    ) -> DescribeTagsOutput:
        raise NotImplementedError

    @handler("DetachLoadBalancerFromSubnets")
    def detach_load_balancer_from_subnets(
        self, context: RequestContext, load_balancer_name: AccessPointName, subnets: Subnets
    ) -> DetachLoadBalancerFromSubnetsOutput:
        raise NotImplementedError

    @handler("DisableAvailabilityZonesForLoadBalancer")
    def disable_availability_zones_for_load_balancer(
        self,
        context: RequestContext,
        load_balancer_name: AccessPointName,
        availability_zones: AvailabilityZones,
    ) -> RemoveAvailabilityZonesOutput:
        raise NotImplementedError

    @handler("EnableAvailabilityZonesForLoadBalancer")
    def enable_availability_zones_for_load_balancer(
        self,
        context: RequestContext,
        load_balancer_name: AccessPointName,
        availability_zones: AvailabilityZones,
    ) -> AddAvailabilityZonesOutput:
        raise NotImplementedError

    @handler("ModifyLoadBalancerAttributes")
    def modify_load_balancer_attributes(
        self,
        context: RequestContext,
        load_balancer_name: AccessPointName,
        load_balancer_attributes: LoadBalancerAttributes,
    ) -> ModifyLoadBalancerAttributesOutput:
        raise NotImplementedError

    @handler("RegisterInstancesWithLoadBalancer")
    def register_instances_with_load_balancer(
        self, context: RequestContext, load_balancer_name: AccessPointName, instances: Instances
    ) -> RegisterEndPointsOutput:
        raise NotImplementedError

    @handler("RemoveTags")
    def remove_tags(
        self, context: RequestContext, load_balancer_names: LoadBalancerNames, tags: TagKeyList
    ) -> RemoveTagsOutput:
        raise NotImplementedError

    @handler("SetLoadBalancerListenerSSLCertificate")
    def set_load_balancer_listener_ssl_certificate(
        self,
        context: RequestContext,
        load_balancer_name: AccessPointName,
        load_balancer_port: AccessPointPort,
        ssl_certificate_id: SSLCertificateId,
    ) -> SetLoadBalancerListenerSSLCertificateOutput:
        raise NotImplementedError

    @handler("SetLoadBalancerPoliciesForBackendServer")
    def set_load_balancer_policies_for_backend_server(
        self,
        context: RequestContext,
        load_balancer_name: AccessPointName,
        instance_port: EndPointPort,
        policy_names: PolicyNames,
    ) -> SetLoadBalancerPoliciesForBackendServerOutput:
        raise NotImplementedError

    @handler("SetLoadBalancerPoliciesOfListener")
    def set_load_balancer_policies_of_listener(
        self,
        context: RequestContext,
        load_balancer_name: AccessPointName,
        load_balancer_port: AccessPointPort,
        policy_names: PolicyNames,
    ) -> SetLoadBalancerPoliciesOfListenerOutput:
        raise NotImplementedError
