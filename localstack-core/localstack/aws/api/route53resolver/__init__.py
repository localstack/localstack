from enum import StrEnum
from typing import TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

AccountId = str
Arn = str
BlockOverrideDomain = str
BlockOverrideTtl = int
Boolean = bool
Count = int
CreatorRequestId = str
DelegationRecord = str
DestinationArn = str
DomainListFileUrl = str
DomainName = str
ExceptionMessage = str
FilterName = str
FilterValue = str
FirewallDomainName = str
FirewallRuleGroupPolicy = str
InstanceCount = int
Ip = str
IpAddressCount = int
Ipv6 = str
ListDomainMaxResults = int
ListFirewallConfigsMaxResult = int
ListResolverConfigsMaxResult = int
MaxResults = int
Name = str
NextToken = str
OutpostArn = str
OutpostInstanceType = str
OutpostResolverName = str
OutpostResolverStatusMessage = str
Port = int
Priority = int
Qtype = str
ResolverQueryLogConfigAssociationErrorMessage = str
ResolverQueryLogConfigName = str
ResolverQueryLogConfigPolicy = str
ResolverRulePolicy = str
ResourceId = str
Rfc3339TimeString = str
RniEnhancedMetricsEnabled = bool
ServerNameIndication = str
ServicePrinciple = str
SortByKey = str
StatusMessage = str
String = str
SubnetId = str
TagKey = str
TagValue = str
TargetNameServerMetricsEnabled = bool
Unsigned = int


class Action(StrEnum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    ALERT = "ALERT"


class AutodefinedReverseFlag(StrEnum):
    ENABLE = "ENABLE"
    DISABLE = "DISABLE"
    USE_LOCAL_RESOURCE_SETTING = "USE_LOCAL_RESOURCE_SETTING"


class BlockOverrideDnsType(StrEnum):
    CNAME = "CNAME"


class BlockResponse(StrEnum):
    NODATA = "NODATA"
    NXDOMAIN = "NXDOMAIN"
    OVERRIDE = "OVERRIDE"


class ConfidenceThreshold(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class DnsThreatProtection(StrEnum):
    DGA = "DGA"
    DNS_TUNNELING = "DNS_TUNNELING"
    DICTIONARY_DGA = "DICTIONARY_DGA"


class FirewallDomainImportOperation(StrEnum):
    REPLACE = "REPLACE"


class FirewallDomainListStatus(StrEnum):
    COMPLETE = "COMPLETE"
    COMPLETE_IMPORT_FAILED = "COMPLETE_IMPORT_FAILED"
    IMPORTING = "IMPORTING"
    DELETING = "DELETING"
    UPDATING = "UPDATING"


class FirewallDomainRedirectionAction(StrEnum):
    INSPECT_REDIRECTION_DOMAIN = "INSPECT_REDIRECTION_DOMAIN"
    TRUST_REDIRECTION_DOMAIN = "TRUST_REDIRECTION_DOMAIN"


class FirewallDomainUpdateOperation(StrEnum):
    ADD = "ADD"
    REMOVE = "REMOVE"
    REPLACE = "REPLACE"


class FirewallFailOpenStatus(StrEnum):
    ENABLED = "ENABLED"
    DISABLED = "DISABLED"
    USE_LOCAL_RESOURCE_SETTING = "USE_LOCAL_RESOURCE_SETTING"


class FirewallRuleGroupAssociationStatus(StrEnum):
    COMPLETE = "COMPLETE"
    DELETING = "DELETING"
    UPDATING = "UPDATING"


class FirewallRuleGroupStatus(StrEnum):
    COMPLETE = "COMPLETE"
    DELETING = "DELETING"
    UPDATING = "UPDATING"


class IpAddressStatus(StrEnum):
    CREATING = "CREATING"
    FAILED_CREATION = "FAILED_CREATION"
    ATTACHING = "ATTACHING"
    ATTACHED = "ATTACHED"
    REMAP_DETACHING = "REMAP_DETACHING"
    REMAP_ATTACHING = "REMAP_ATTACHING"
    DETACHING = "DETACHING"
    FAILED_RESOURCE_GONE = "FAILED_RESOURCE_GONE"
    DELETING = "DELETING"
    DELETE_FAILED_FAS_EXPIRED = "DELETE_FAILED_FAS_EXPIRED"
    UPDATING = "UPDATING"
    UPDATE_FAILED = "UPDATE_FAILED"
    ISOLATED = "ISOLATED"


class MutationProtectionStatus(StrEnum):
    ENABLED = "ENABLED"
    DISABLED = "DISABLED"


class OutpostResolverStatus(StrEnum):
    CREATING = "CREATING"
    OPERATIONAL = "OPERATIONAL"
    UPDATING = "UPDATING"
    DELETING = "DELETING"
    ACTION_NEEDED = "ACTION_NEEDED"
    FAILED_CREATION = "FAILED_CREATION"
    FAILED_DELETION = "FAILED_DELETION"


class Protocol(StrEnum):
    DoH = "DoH"
    Do53 = "Do53"
    DoH_FIPS = "DoH-FIPS"


class ResolverAutodefinedReverseStatus(StrEnum):
    ENABLING = "ENABLING"
    ENABLED = "ENABLED"
    DISABLING = "DISABLING"
    DISABLED = "DISABLED"
    UPDATING_TO_USE_LOCAL_RESOURCE_SETTING = "UPDATING_TO_USE_LOCAL_RESOURCE_SETTING"
    USE_LOCAL_RESOURCE_SETTING = "USE_LOCAL_RESOURCE_SETTING"


class ResolverDNSSECValidationStatus(StrEnum):
    ENABLING = "ENABLING"
    ENABLED = "ENABLED"
    DISABLING = "DISABLING"
    DISABLED = "DISABLED"
    UPDATING_TO_USE_LOCAL_RESOURCE_SETTING = "UPDATING_TO_USE_LOCAL_RESOURCE_SETTING"
    USE_LOCAL_RESOURCE_SETTING = "USE_LOCAL_RESOURCE_SETTING"


class ResolverEndpointDirection(StrEnum):
    INBOUND = "INBOUND"
    OUTBOUND = "OUTBOUND"
    INBOUND_DELEGATION = "INBOUND_DELEGATION"


class ResolverEndpointStatus(StrEnum):
    CREATING = "CREATING"
    OPERATIONAL = "OPERATIONAL"
    UPDATING = "UPDATING"
    AUTO_RECOVERING = "AUTO_RECOVERING"
    ACTION_NEEDED = "ACTION_NEEDED"
    DELETING = "DELETING"


class ResolverEndpointType(StrEnum):
    IPV6 = "IPV6"
    IPV4 = "IPV4"
    DUALSTACK = "DUALSTACK"


class ResolverQueryLogConfigAssociationError(StrEnum):
    NONE = "NONE"
    DESTINATION_NOT_FOUND = "DESTINATION_NOT_FOUND"
    ACCESS_DENIED = "ACCESS_DENIED"
    INTERNAL_SERVICE_ERROR = "INTERNAL_SERVICE_ERROR"


class ResolverQueryLogConfigAssociationStatus(StrEnum):
    CREATING = "CREATING"
    ACTIVE = "ACTIVE"
    ACTION_NEEDED = "ACTION_NEEDED"
    DELETING = "DELETING"
    FAILED = "FAILED"


class ResolverQueryLogConfigStatus(StrEnum):
    CREATING = "CREATING"
    CREATED = "CREATED"
    DELETING = "DELETING"
    FAILED = "FAILED"


class ResolverRuleAssociationStatus(StrEnum):
    CREATING = "CREATING"
    COMPLETE = "COMPLETE"
    DELETING = "DELETING"
    FAILED = "FAILED"
    OVERRIDDEN = "OVERRIDDEN"


class ResolverRuleStatus(StrEnum):
    COMPLETE = "COMPLETE"
    DELETING = "DELETING"
    UPDATING = "UPDATING"
    FAILED = "FAILED"


class RuleTypeOption(StrEnum):
    FORWARD = "FORWARD"
    SYSTEM = "SYSTEM"
    RECURSIVE = "RECURSIVE"
    DELEGATE = "DELEGATE"


class ShareStatus(StrEnum):
    NOT_SHARED = "NOT_SHARED"
    SHARED_WITH_ME = "SHARED_WITH_ME"
    SHARED_BY_ME = "SHARED_BY_ME"


class SortOrder(StrEnum):
    ASCENDING = "ASCENDING"
    DESCENDING = "DESCENDING"


class Validation(StrEnum):
    ENABLE = "ENABLE"
    DISABLE = "DISABLE"
    USE_LOCAL_RESOURCE_SETTING = "USE_LOCAL_RESOURCE_SETTING"


class AccessDeniedException(ServiceException):
    code: str = "AccessDeniedException"
    sender_fault: bool = False
    status_code: int = 400


class ConflictException(ServiceException):
    code: str = "ConflictException"
    sender_fault: bool = False
    status_code: int = 400


class InternalServiceErrorException(ServiceException):
    code: str = "InternalServiceErrorException"
    sender_fault: bool = False
    status_code: int = 400


class InvalidNextTokenException(ServiceException):
    code: str = "InvalidNextTokenException"
    sender_fault: bool = False
    status_code: int = 400


class InvalidParameterException(ServiceException):
    code: str = "InvalidParameterException"
    sender_fault: bool = False
    status_code: int = 400
    FieldName: String | None


class InvalidPolicyDocument(ServiceException):
    code: str = "InvalidPolicyDocument"
    sender_fault: bool = False
    status_code: int = 400


class InvalidRequestException(ServiceException):
    code: str = "InvalidRequestException"
    sender_fault: bool = False
    status_code: int = 400


class InvalidTagException(ServiceException):
    code: str = "InvalidTagException"
    sender_fault: bool = False
    status_code: int = 400


class LimitExceededException(ServiceException):
    code: str = "LimitExceededException"
    sender_fault: bool = False
    status_code: int = 400
    ResourceType: String | None


class ResourceExistsException(ServiceException):
    code: str = "ResourceExistsException"
    sender_fault: bool = False
    status_code: int = 400
    ResourceType: String | None


class ResourceInUseException(ServiceException):
    code: str = "ResourceInUseException"
    sender_fault: bool = False
    status_code: int = 400
    ResourceType: String | None


class ResourceNotFoundException(ServiceException):
    code: str = "ResourceNotFoundException"
    sender_fault: bool = False
    status_code: int = 400
    ResourceType: String | None


class ResourceUnavailableException(ServiceException):
    code: str = "ResourceUnavailableException"
    sender_fault: bool = False
    status_code: int = 400
    ResourceType: String | None


class ServiceQuotaExceededException(ServiceException):
    code: str = "ServiceQuotaExceededException"
    sender_fault: bool = False
    status_code: int = 400


class ThrottlingException(ServiceException):
    code: str = "ThrottlingException"
    sender_fault: bool = False
    status_code: int = 400


class UnknownResourceException(ServiceException):
    code: str = "UnknownResourceException"
    sender_fault: bool = False
    status_code: int = 400


class ValidationException(ServiceException):
    code: str = "ValidationException"
    sender_fault: bool = False
    status_code: int = 400


class Tag(TypedDict, total=False):
    Key: TagKey
    Value: TagValue


TagList = list[Tag]


class AssociateFirewallRuleGroupRequest(ServiceRequest):
    CreatorRequestId: CreatorRequestId
    FirewallRuleGroupId: ResourceId
    VpcId: ResourceId
    Priority: Priority
    Name: Name
    MutationProtection: MutationProtectionStatus | None
    Tags: TagList | None


class FirewallRuleGroupAssociation(TypedDict, total=False):
    Id: ResourceId | None
    Arn: Arn | None
    FirewallRuleGroupId: ResourceId | None
    VpcId: ResourceId | None
    Name: Name | None
    Priority: Priority | None
    MutationProtection: MutationProtectionStatus | None
    ManagedOwnerName: ServicePrinciple | None
    Status: FirewallRuleGroupAssociationStatus | None
    StatusMessage: StatusMessage | None
    CreatorRequestId: CreatorRequestId | None
    CreationTime: Rfc3339TimeString | None
    ModificationTime: Rfc3339TimeString | None


class AssociateFirewallRuleGroupResponse(TypedDict, total=False):
    FirewallRuleGroupAssociation: FirewallRuleGroupAssociation | None


class IpAddressUpdate(TypedDict, total=False):
    IpId: ResourceId | None
    SubnetId: SubnetId | None
    Ip: Ip | None
    Ipv6: Ipv6 | None


class AssociateResolverEndpointIpAddressRequest(ServiceRequest):
    ResolverEndpointId: ResourceId
    IpAddress: IpAddressUpdate


ProtocolList = list[Protocol]
SecurityGroupIds = list[ResourceId]


class ResolverEndpoint(TypedDict, total=False):
    Id: ResourceId | None
    CreatorRequestId: CreatorRequestId | None
    Arn: Arn | None
    Name: Name | None
    SecurityGroupIds: SecurityGroupIds | None
    Direction: ResolverEndpointDirection | None
    IpAddressCount: IpAddressCount | None
    HostVPCId: ResourceId | None
    Status: ResolverEndpointStatus | None
    StatusMessage: StatusMessage | None
    CreationTime: Rfc3339TimeString | None
    ModificationTime: Rfc3339TimeString | None
    OutpostArn: OutpostArn | None
    PreferredInstanceType: OutpostInstanceType | None
    ResolverEndpointType: ResolverEndpointType | None
    Protocols: ProtocolList | None
    RniEnhancedMetricsEnabled: RniEnhancedMetricsEnabled | None
    TargetNameServerMetricsEnabled: TargetNameServerMetricsEnabled | None


class AssociateResolverEndpointIpAddressResponse(TypedDict, total=False):
    ResolverEndpoint: ResolverEndpoint | None


class AssociateResolverQueryLogConfigRequest(ServiceRequest):
    ResolverQueryLogConfigId: ResourceId
    ResourceId: ResourceId


class ResolverQueryLogConfigAssociation(TypedDict, total=False):
    Id: ResourceId | None
    ResolverQueryLogConfigId: ResourceId | None
    ResourceId: ResourceId | None
    Status: ResolverQueryLogConfigAssociationStatus | None
    Error: ResolverQueryLogConfigAssociationError | None
    ErrorMessage: ResolverQueryLogConfigAssociationErrorMessage | None
    CreationTime: Rfc3339TimeString | None


class AssociateResolverQueryLogConfigResponse(TypedDict, total=False):
    ResolverQueryLogConfigAssociation: ResolverQueryLogConfigAssociation | None


class AssociateResolverRuleRequest(ServiceRequest):
    ResolverRuleId: ResourceId
    Name: Name | None
    VPCId: ResourceId


class ResolverRuleAssociation(TypedDict, total=False):
    Id: ResourceId | None
    ResolverRuleId: ResourceId | None
    Name: Name | None
    VPCId: ResourceId | None
    Status: ResolverRuleAssociationStatus | None
    StatusMessage: StatusMessage | None


class AssociateResolverRuleResponse(TypedDict, total=False):
    ResolverRuleAssociation: ResolverRuleAssociation | None


class CreateFirewallDomainListRequest(ServiceRequest):
    CreatorRequestId: CreatorRequestId
    Name: Name
    Tags: TagList | None


class FirewallDomainList(TypedDict, total=False):
    Id: ResourceId | None
    Arn: Arn | None
    Name: Name | None
    DomainCount: Unsigned | None
    Status: FirewallDomainListStatus | None
    StatusMessage: StatusMessage | None
    ManagedOwnerName: ServicePrinciple | None
    CreatorRequestId: CreatorRequestId | None
    CreationTime: Rfc3339TimeString | None
    ModificationTime: Rfc3339TimeString | None


class CreateFirewallDomainListResponse(TypedDict, total=False):
    FirewallDomainList: FirewallDomainList | None


class CreateFirewallRuleGroupRequest(ServiceRequest):
    CreatorRequestId: CreatorRequestId
    Name: Name
    Tags: TagList | None


class FirewallRuleGroup(TypedDict, total=False):
    Id: ResourceId | None
    Arn: Arn | None
    Name: Name | None
    RuleCount: Unsigned | None
    Status: FirewallRuleGroupStatus | None
    StatusMessage: StatusMessage | None
    OwnerId: AccountId | None
    CreatorRequestId: CreatorRequestId | None
    ShareStatus: ShareStatus | None
    CreationTime: Rfc3339TimeString | None
    ModificationTime: Rfc3339TimeString | None


class CreateFirewallRuleGroupResponse(TypedDict, total=False):
    FirewallRuleGroup: FirewallRuleGroup | None


class CreateFirewallRuleRequest(ServiceRequest):
    CreatorRequestId: CreatorRequestId
    FirewallRuleGroupId: ResourceId
    FirewallDomainListId: ResourceId | None
    Priority: Priority
    Action: Action
    BlockResponse: BlockResponse | None
    BlockOverrideDomain: BlockOverrideDomain | None
    BlockOverrideDnsType: BlockOverrideDnsType | None
    BlockOverrideTtl: BlockOverrideTtl | None
    Name: Name
    FirewallDomainRedirectionAction: FirewallDomainRedirectionAction | None
    Qtype: Qtype | None
    DnsThreatProtection: DnsThreatProtection | None
    ConfidenceThreshold: ConfidenceThreshold | None


class FirewallRule(TypedDict, total=False):
    FirewallRuleGroupId: ResourceId | None
    FirewallDomainListId: ResourceId | None
    FirewallThreatProtectionId: ResourceId | None
    Name: Name | None
    Priority: Priority | None
    Action: Action | None
    BlockResponse: BlockResponse | None
    BlockOverrideDomain: BlockOverrideDomain | None
    BlockOverrideDnsType: BlockOverrideDnsType | None
    BlockOverrideTtl: Unsigned | None
    CreatorRequestId: CreatorRequestId | None
    CreationTime: Rfc3339TimeString | None
    ModificationTime: Rfc3339TimeString | None
    FirewallDomainRedirectionAction: FirewallDomainRedirectionAction | None
    Qtype: Qtype | None
    DnsThreatProtection: DnsThreatProtection | None
    ConfidenceThreshold: ConfidenceThreshold | None


class CreateFirewallRuleResponse(TypedDict, total=False):
    FirewallRule: FirewallRule | None


class CreateOutpostResolverRequest(ServiceRequest):
    CreatorRequestId: CreatorRequestId
    Name: OutpostResolverName
    InstanceCount: InstanceCount | None
    PreferredInstanceType: OutpostInstanceType
    OutpostArn: OutpostArn
    Tags: TagList | None


class OutpostResolver(TypedDict, total=False):
    Arn: Arn | None
    CreationTime: Rfc3339TimeString | None
    ModificationTime: Rfc3339TimeString | None
    CreatorRequestId: CreatorRequestId | None
    Id: ResourceId | None
    InstanceCount: InstanceCount | None
    PreferredInstanceType: OutpostInstanceType | None
    Name: OutpostResolverName | None
    Status: OutpostResolverStatus | None
    StatusMessage: OutpostResolverStatusMessage | None
    OutpostArn: OutpostArn | None


class CreateOutpostResolverResponse(TypedDict, total=False):
    OutpostResolver: OutpostResolver | None


class IpAddressRequest(TypedDict, total=False):
    SubnetId: SubnetId
    Ip: Ip | None
    Ipv6: Ipv6 | None


IpAddressesRequest = list[IpAddressRequest]


class CreateResolverEndpointRequest(ServiceRequest):
    CreatorRequestId: CreatorRequestId
    Name: Name | None
    SecurityGroupIds: SecurityGroupIds
    Direction: ResolverEndpointDirection
    IpAddresses: IpAddressesRequest
    OutpostArn: OutpostArn | None
    PreferredInstanceType: OutpostInstanceType | None
    Tags: TagList | None
    ResolverEndpointType: ResolverEndpointType | None
    Protocols: ProtocolList | None
    RniEnhancedMetricsEnabled: RniEnhancedMetricsEnabled | None
    TargetNameServerMetricsEnabled: TargetNameServerMetricsEnabled | None


class CreateResolverEndpointResponse(TypedDict, total=False):
    ResolverEndpoint: ResolverEndpoint | None


class CreateResolverQueryLogConfigRequest(ServiceRequest):
    Name: ResolverQueryLogConfigName
    DestinationArn: DestinationArn
    CreatorRequestId: CreatorRequestId
    Tags: TagList | None


class ResolverQueryLogConfig(TypedDict, total=False):
    Id: ResourceId | None
    OwnerId: AccountId | None
    Status: ResolverQueryLogConfigStatus | None
    ShareStatus: ShareStatus | None
    AssociationCount: Count | None
    Arn: Arn | None
    Name: ResolverQueryLogConfigName | None
    DestinationArn: DestinationArn | None
    CreatorRequestId: CreatorRequestId | None
    CreationTime: Rfc3339TimeString | None


class CreateResolverQueryLogConfigResponse(TypedDict, total=False):
    ResolverQueryLogConfig: ResolverQueryLogConfig | None


class TargetAddress(TypedDict, total=False):
    Ip: Ip | None
    Port: Port | None
    Ipv6: Ipv6 | None
    Protocol: Protocol | None
    ServerNameIndication: ServerNameIndication | None


TargetList = list[TargetAddress]


class CreateResolverRuleRequest(ServiceRequest):
    CreatorRequestId: CreatorRequestId
    Name: Name | None
    RuleType: RuleTypeOption
    DomainName: DomainName | None
    TargetIps: TargetList | None
    ResolverEndpointId: ResourceId | None
    Tags: TagList | None
    DelegationRecord: DelegationRecord | None


class ResolverRule(TypedDict, total=False):
    Id: ResourceId | None
    CreatorRequestId: CreatorRequestId | None
    Arn: Arn | None
    DomainName: DomainName | None
    Status: ResolverRuleStatus | None
    StatusMessage: StatusMessage | None
    RuleType: RuleTypeOption | None
    Name: Name | None
    TargetIps: TargetList | None
    ResolverEndpointId: ResourceId | None
    OwnerId: AccountId | None
    ShareStatus: ShareStatus | None
    CreationTime: Rfc3339TimeString | None
    ModificationTime: Rfc3339TimeString | None
    DelegationRecord: DelegationRecord | None


class CreateResolverRuleResponse(TypedDict, total=False):
    ResolverRule: ResolverRule | None


class DeleteFirewallDomainListRequest(ServiceRequest):
    FirewallDomainListId: ResourceId


class DeleteFirewallDomainListResponse(TypedDict, total=False):
    FirewallDomainList: FirewallDomainList | None


class DeleteFirewallRuleGroupRequest(ServiceRequest):
    FirewallRuleGroupId: ResourceId


class DeleteFirewallRuleGroupResponse(TypedDict, total=False):
    FirewallRuleGroup: FirewallRuleGroup | None


class DeleteFirewallRuleRequest(ServiceRequest):
    FirewallRuleGroupId: ResourceId
    FirewallDomainListId: ResourceId | None
    FirewallThreatProtectionId: ResourceId | None
    Qtype: Qtype | None


class DeleteFirewallRuleResponse(TypedDict, total=False):
    FirewallRule: FirewallRule | None


class DeleteOutpostResolverRequest(ServiceRequest):
    Id: ResourceId


class DeleteOutpostResolverResponse(TypedDict, total=False):
    OutpostResolver: OutpostResolver | None


class DeleteResolverEndpointRequest(ServiceRequest):
    ResolverEndpointId: ResourceId


class DeleteResolverEndpointResponse(TypedDict, total=False):
    ResolverEndpoint: ResolverEndpoint | None


class DeleteResolverQueryLogConfigRequest(ServiceRequest):
    ResolverQueryLogConfigId: ResourceId


class DeleteResolverQueryLogConfigResponse(TypedDict, total=False):
    ResolverQueryLogConfig: ResolverQueryLogConfig | None


class DeleteResolverRuleRequest(ServiceRequest):
    ResolverRuleId: ResourceId


class DeleteResolverRuleResponse(TypedDict, total=False):
    ResolverRule: ResolverRule | None


class DisassociateFirewallRuleGroupRequest(ServiceRequest):
    FirewallRuleGroupAssociationId: ResourceId


class DisassociateFirewallRuleGroupResponse(TypedDict, total=False):
    FirewallRuleGroupAssociation: FirewallRuleGroupAssociation | None


class DisassociateResolverEndpointIpAddressRequest(ServiceRequest):
    ResolverEndpointId: ResourceId
    IpAddress: IpAddressUpdate


class DisassociateResolverEndpointIpAddressResponse(TypedDict, total=False):
    ResolverEndpoint: ResolverEndpoint | None


class DisassociateResolverQueryLogConfigRequest(ServiceRequest):
    ResolverQueryLogConfigId: ResourceId
    ResourceId: ResourceId


class DisassociateResolverQueryLogConfigResponse(TypedDict, total=False):
    ResolverQueryLogConfigAssociation: ResolverQueryLogConfigAssociation | None


class DisassociateResolverRuleRequest(ServiceRequest):
    VPCId: ResourceId
    ResolverRuleId: ResourceId


class DisassociateResolverRuleResponse(TypedDict, total=False):
    ResolverRuleAssociation: ResolverRuleAssociation | None


FilterValues = list[FilterValue]


class Filter(TypedDict, total=False):
    Name: FilterName | None
    Values: FilterValues | None


Filters = list[Filter]


class FirewallConfig(TypedDict, total=False):
    Id: ResourceId | None
    ResourceId: ResourceId | None
    OwnerId: AccountId | None
    FirewallFailOpen: FirewallFailOpenStatus | None


FirewallConfigList = list[FirewallConfig]


class FirewallDomainListMetadata(TypedDict, total=False):
    Id: ResourceId | None
    Arn: Arn | None
    Name: Name | None
    CreatorRequestId: CreatorRequestId | None
    ManagedOwnerName: ServicePrinciple | None


FirewallDomainListMetadataList = list[FirewallDomainListMetadata]
FirewallDomains = list[FirewallDomainName]
FirewallRuleGroupAssociations = list[FirewallRuleGroupAssociation]


class FirewallRuleGroupMetadata(TypedDict, total=False):
    Id: ResourceId | None
    Arn: Arn | None
    Name: Name | None
    OwnerId: AccountId | None
    CreatorRequestId: CreatorRequestId | None
    ShareStatus: ShareStatus | None


FirewallRuleGroupMetadataList = list[FirewallRuleGroupMetadata]
FirewallRules = list[FirewallRule]


class GetFirewallConfigRequest(ServiceRequest):
    ResourceId: ResourceId


class GetFirewallConfigResponse(TypedDict, total=False):
    FirewallConfig: FirewallConfig | None


class GetFirewallDomainListRequest(ServiceRequest):
    FirewallDomainListId: ResourceId


class GetFirewallDomainListResponse(TypedDict, total=False):
    FirewallDomainList: FirewallDomainList | None


class GetFirewallRuleGroupAssociationRequest(ServiceRequest):
    FirewallRuleGroupAssociationId: ResourceId


class GetFirewallRuleGroupAssociationResponse(TypedDict, total=False):
    FirewallRuleGroupAssociation: FirewallRuleGroupAssociation | None


class GetFirewallRuleGroupPolicyRequest(ServiceRequest):
    Arn: Arn


class GetFirewallRuleGroupPolicyResponse(TypedDict, total=False):
    FirewallRuleGroupPolicy: FirewallRuleGroupPolicy | None


class GetFirewallRuleGroupRequest(ServiceRequest):
    FirewallRuleGroupId: ResourceId


class GetFirewallRuleGroupResponse(TypedDict, total=False):
    FirewallRuleGroup: FirewallRuleGroup | None


class GetOutpostResolverRequest(ServiceRequest):
    Id: ResourceId


class GetOutpostResolverResponse(TypedDict, total=False):
    OutpostResolver: OutpostResolver | None


class GetResolverConfigRequest(ServiceRequest):
    ResourceId: ResourceId


class ResolverConfig(TypedDict, total=False):
    Id: ResourceId | None
    ResourceId: ResourceId | None
    OwnerId: AccountId | None
    AutodefinedReverse: ResolverAutodefinedReverseStatus | None


class GetResolverConfigResponse(TypedDict, total=False):
    ResolverConfig: ResolverConfig | None


class GetResolverDnssecConfigRequest(ServiceRequest):
    ResourceId: ResourceId


class ResolverDnssecConfig(TypedDict, total=False):
    Id: ResourceId | None
    OwnerId: AccountId | None
    ResourceId: ResourceId | None
    ValidationStatus: ResolverDNSSECValidationStatus | None


class GetResolverDnssecConfigResponse(TypedDict, total=False):
    ResolverDNSSECConfig: ResolverDnssecConfig | None


class GetResolverEndpointRequest(ServiceRequest):
    ResolverEndpointId: ResourceId


class GetResolverEndpointResponse(TypedDict, total=False):
    ResolverEndpoint: ResolverEndpoint | None


class GetResolverQueryLogConfigAssociationRequest(ServiceRequest):
    ResolverQueryLogConfigAssociationId: ResourceId


class GetResolverQueryLogConfigAssociationResponse(TypedDict, total=False):
    ResolverQueryLogConfigAssociation: ResolverQueryLogConfigAssociation | None


class GetResolverQueryLogConfigPolicyRequest(ServiceRequest):
    Arn: Arn


class GetResolverQueryLogConfigPolicyResponse(TypedDict, total=False):
    ResolverQueryLogConfigPolicy: ResolverQueryLogConfigPolicy | None


class GetResolverQueryLogConfigRequest(ServiceRequest):
    ResolverQueryLogConfigId: ResourceId


class GetResolverQueryLogConfigResponse(TypedDict, total=False):
    ResolverQueryLogConfig: ResolverQueryLogConfig | None


class GetResolverRuleAssociationRequest(ServiceRequest):
    ResolverRuleAssociationId: ResourceId


class GetResolverRuleAssociationResponse(TypedDict, total=False):
    ResolverRuleAssociation: ResolverRuleAssociation | None


class GetResolverRulePolicyRequest(ServiceRequest):
    Arn: Arn


class GetResolverRulePolicyResponse(TypedDict, total=False):
    ResolverRulePolicy: ResolverRulePolicy | None


class GetResolverRuleRequest(ServiceRequest):
    ResolverRuleId: ResourceId


class GetResolverRuleResponse(TypedDict, total=False):
    ResolverRule: ResolverRule | None


class ImportFirewallDomainsRequest(ServiceRequest):
    FirewallDomainListId: ResourceId
    Operation: FirewallDomainImportOperation
    DomainFileUrl: DomainListFileUrl


class ImportFirewallDomainsResponse(TypedDict, total=False):
    Id: ResourceId | None
    Name: Name | None
    Status: FirewallDomainListStatus | None
    StatusMessage: StatusMessage | None


class IpAddressResponse(TypedDict, total=False):
    IpId: ResourceId | None
    SubnetId: SubnetId | None
    Ip: Ip | None
    Ipv6: Ipv6 | None
    Status: IpAddressStatus | None
    StatusMessage: StatusMessage | None
    CreationTime: Rfc3339TimeString | None
    ModificationTime: Rfc3339TimeString | None


IpAddressesResponse = list[IpAddressResponse]


class ListFirewallConfigsRequest(ServiceRequest):
    MaxResults: ListFirewallConfigsMaxResult | None
    NextToken: NextToken | None


class ListFirewallConfigsResponse(TypedDict, total=False):
    NextToken: NextToken | None
    FirewallConfigs: FirewallConfigList | None


class ListFirewallDomainListsRequest(ServiceRequest):
    MaxResults: MaxResults | None
    NextToken: NextToken | None


class ListFirewallDomainListsResponse(TypedDict, total=False):
    NextToken: NextToken | None
    FirewallDomainLists: FirewallDomainListMetadataList | None


class ListFirewallDomainsRequest(ServiceRequest):
    FirewallDomainListId: ResourceId
    MaxResults: ListDomainMaxResults | None
    NextToken: NextToken | None


class ListFirewallDomainsResponse(TypedDict, total=False):
    NextToken: NextToken | None
    Domains: FirewallDomains | None


class ListFirewallRuleGroupAssociationsRequest(ServiceRequest):
    FirewallRuleGroupId: ResourceId | None
    VpcId: ResourceId | None
    Priority: Priority | None
    Status: FirewallRuleGroupAssociationStatus | None
    MaxResults: MaxResults | None
    NextToken: NextToken | None


class ListFirewallRuleGroupAssociationsResponse(TypedDict, total=False):
    NextToken: NextToken | None
    FirewallRuleGroupAssociations: FirewallRuleGroupAssociations | None


class ListFirewallRuleGroupsRequest(ServiceRequest):
    MaxResults: MaxResults | None
    NextToken: NextToken | None


class ListFirewallRuleGroupsResponse(TypedDict, total=False):
    NextToken: NextToken | None
    FirewallRuleGroups: FirewallRuleGroupMetadataList | None


class ListFirewallRulesRequest(ServiceRequest):
    FirewallRuleGroupId: ResourceId
    Priority: Priority | None
    Action: Action | None
    MaxResults: MaxResults | None
    NextToken: NextToken | None


class ListFirewallRulesResponse(TypedDict, total=False):
    NextToken: NextToken | None
    FirewallRules: FirewallRules | None


class ListOutpostResolversRequest(ServiceRequest):
    OutpostArn: OutpostArn | None
    MaxResults: MaxResults | None
    NextToken: NextToken | None


OutpostResolverList = list[OutpostResolver]


class ListOutpostResolversResponse(TypedDict, total=False):
    OutpostResolvers: OutpostResolverList | None
    NextToken: NextToken | None


class ListResolverConfigsRequest(ServiceRequest):
    MaxResults: ListResolverConfigsMaxResult | None
    NextToken: NextToken | None


ResolverConfigList = list[ResolverConfig]


class ListResolverConfigsResponse(TypedDict, total=False):
    NextToken: NextToken | None
    ResolverConfigs: ResolverConfigList | None


class ListResolverDnssecConfigsRequest(ServiceRequest):
    MaxResults: MaxResults | None
    NextToken: NextToken | None
    Filters: Filters | None


ResolverDnssecConfigList = list[ResolverDnssecConfig]


class ListResolverDnssecConfigsResponse(TypedDict, total=False):
    NextToken: NextToken | None
    ResolverDnssecConfigs: ResolverDnssecConfigList | None


class ListResolverEndpointIpAddressesRequest(ServiceRequest):
    ResolverEndpointId: ResourceId
    MaxResults: MaxResults | None
    NextToken: NextToken | None


class ListResolverEndpointIpAddressesResponse(TypedDict, total=False):
    NextToken: NextToken | None
    MaxResults: MaxResults | None
    IpAddresses: IpAddressesResponse | None


class ListResolverEndpointsRequest(ServiceRequest):
    MaxResults: MaxResults | None
    NextToken: NextToken | None
    Filters: Filters | None


ResolverEndpoints = list[ResolverEndpoint]


class ListResolverEndpointsResponse(TypedDict, total=False):
    NextToken: NextToken | None
    MaxResults: MaxResults | None
    ResolverEndpoints: ResolverEndpoints | None


class ListResolverQueryLogConfigAssociationsRequest(ServiceRequest):
    MaxResults: MaxResults | None
    NextToken: NextToken | None
    Filters: Filters | None
    SortBy: SortByKey | None
    SortOrder: SortOrder | None


ResolverQueryLogConfigAssociationList = list[ResolverQueryLogConfigAssociation]


class ListResolverQueryLogConfigAssociationsResponse(TypedDict, total=False):
    NextToken: NextToken | None
    TotalCount: Count | None
    TotalFilteredCount: Count | None
    ResolverQueryLogConfigAssociations: ResolverQueryLogConfigAssociationList | None


class ListResolverQueryLogConfigsRequest(ServiceRequest):
    MaxResults: MaxResults | None
    NextToken: NextToken | None
    Filters: Filters | None
    SortBy: SortByKey | None
    SortOrder: SortOrder | None


ResolverQueryLogConfigList = list[ResolverQueryLogConfig]


class ListResolverQueryLogConfigsResponse(TypedDict, total=False):
    NextToken: NextToken | None
    TotalCount: Count | None
    TotalFilteredCount: Count | None
    ResolverQueryLogConfigs: ResolverQueryLogConfigList | None


class ListResolverRuleAssociationsRequest(ServiceRequest):
    MaxResults: MaxResults | None
    NextToken: NextToken | None
    Filters: Filters | None


ResolverRuleAssociations = list[ResolverRuleAssociation]


class ListResolverRuleAssociationsResponse(TypedDict, total=False):
    NextToken: NextToken | None
    MaxResults: MaxResults | None
    ResolverRuleAssociations: ResolverRuleAssociations | None


class ListResolverRulesRequest(ServiceRequest):
    MaxResults: MaxResults | None
    NextToken: NextToken | None
    Filters: Filters | None


ResolverRules = list[ResolverRule]


class ListResolverRulesResponse(TypedDict, total=False):
    NextToken: NextToken | None
    MaxResults: MaxResults | None
    ResolverRules: ResolverRules | None


class ListTagsForResourceRequest(ServiceRequest):
    ResourceArn: Arn
    MaxResults: MaxResults | None
    NextToken: NextToken | None


class ListTagsForResourceResponse(TypedDict, total=False):
    Tags: TagList | None
    NextToken: NextToken | None


class PutFirewallRuleGroupPolicyRequest(ServiceRequest):
    Arn: Arn
    FirewallRuleGroupPolicy: FirewallRuleGroupPolicy


class PutFirewallRuleGroupPolicyResponse(TypedDict, total=False):
    ReturnValue: Boolean | None


class PutResolverQueryLogConfigPolicyRequest(ServiceRequest):
    Arn: Arn
    ResolverQueryLogConfigPolicy: ResolverQueryLogConfigPolicy


class PutResolverQueryLogConfigPolicyResponse(TypedDict, total=False):
    ReturnValue: Boolean | None


class PutResolverRulePolicyRequest(ServiceRequest):
    Arn: Arn
    ResolverRulePolicy: ResolverRulePolicy


class PutResolverRulePolicyResponse(TypedDict, total=False):
    ReturnValue: Boolean | None


class ResolverRuleConfig(TypedDict, total=False):
    Name: Name | None
    TargetIps: TargetList | None
    ResolverEndpointId: ResourceId | None


TagKeyList = list[TagKey]


class TagResourceRequest(ServiceRequest):
    ResourceArn: Arn
    Tags: TagList


class TagResourceResponse(TypedDict, total=False):
    pass


class UntagResourceRequest(ServiceRequest):
    ResourceArn: Arn
    TagKeys: TagKeyList


class UntagResourceResponse(TypedDict, total=False):
    pass


class UpdateFirewallConfigRequest(ServiceRequest):
    ResourceId: ResourceId
    FirewallFailOpen: FirewallFailOpenStatus


class UpdateFirewallConfigResponse(TypedDict, total=False):
    FirewallConfig: FirewallConfig | None


class UpdateFirewallDomainsRequest(ServiceRequest):
    FirewallDomainListId: ResourceId
    Operation: FirewallDomainUpdateOperation
    Domains: FirewallDomains


class UpdateFirewallDomainsResponse(TypedDict, total=False):
    Id: ResourceId | None
    Name: Name | None
    Status: FirewallDomainListStatus | None
    StatusMessage: StatusMessage | None


class UpdateFirewallRuleGroupAssociationRequest(ServiceRequest):
    FirewallRuleGroupAssociationId: ResourceId
    Priority: Priority | None
    MutationProtection: MutationProtectionStatus | None
    Name: Name | None


class UpdateFirewallRuleGroupAssociationResponse(TypedDict, total=False):
    FirewallRuleGroupAssociation: FirewallRuleGroupAssociation | None


class UpdateFirewallRuleRequest(ServiceRequest):
    FirewallRuleGroupId: ResourceId
    FirewallDomainListId: ResourceId | None
    FirewallThreatProtectionId: ResourceId | None
    Priority: Priority | None
    Action: Action | None
    BlockResponse: BlockResponse | None
    BlockOverrideDomain: BlockOverrideDomain | None
    BlockOverrideDnsType: BlockOverrideDnsType | None
    BlockOverrideTtl: BlockOverrideTtl | None
    Name: Name | None
    FirewallDomainRedirectionAction: FirewallDomainRedirectionAction | None
    Qtype: Qtype | None
    DnsThreatProtection: DnsThreatProtection | None
    ConfidenceThreshold: ConfidenceThreshold | None


class UpdateFirewallRuleResponse(TypedDict, total=False):
    FirewallRule: FirewallRule | None


class UpdateIpAddress(TypedDict, total=False):
    IpId: ResourceId
    Ipv6: Ipv6


UpdateIpAddresses = list[UpdateIpAddress]


class UpdateOutpostResolverRequest(ServiceRequest):
    Id: ResourceId
    Name: OutpostResolverName | None
    InstanceCount: InstanceCount | None
    PreferredInstanceType: OutpostInstanceType | None


class UpdateOutpostResolverResponse(TypedDict, total=False):
    OutpostResolver: OutpostResolver | None


class UpdateResolverConfigRequest(ServiceRequest):
    ResourceId: ResourceId
    AutodefinedReverseFlag: AutodefinedReverseFlag


class UpdateResolverConfigResponse(TypedDict, total=False):
    ResolverConfig: ResolverConfig | None


class UpdateResolverDnssecConfigRequest(ServiceRequest):
    ResourceId: ResourceId
    Validation: Validation


class UpdateResolverDnssecConfigResponse(TypedDict, total=False):
    ResolverDNSSECConfig: ResolverDnssecConfig | None


class UpdateResolverEndpointRequest(ServiceRequest):
    ResolverEndpointId: ResourceId
    Name: Name | None
    ResolverEndpointType: ResolverEndpointType | None
    UpdateIpAddresses: UpdateIpAddresses | None
    Protocols: ProtocolList | None
    RniEnhancedMetricsEnabled: RniEnhancedMetricsEnabled | None
    TargetNameServerMetricsEnabled: TargetNameServerMetricsEnabled | None


class UpdateResolverEndpointResponse(TypedDict, total=False):
    ResolverEndpoint: ResolverEndpoint | None


class UpdateResolverRuleRequest(ServiceRequest):
    ResolverRuleId: ResourceId
    Config: ResolverRuleConfig


class UpdateResolverRuleResponse(TypedDict, total=False):
    ResolverRule: ResolverRule | None


class Route53ResolverApi:
    service: str = "route53resolver"
    version: str = "2018-04-01"

    @handler("AssociateFirewallRuleGroup")
    def associate_firewall_rule_group(
        self,
        context: RequestContext,
        creator_request_id: CreatorRequestId,
        firewall_rule_group_id: ResourceId,
        vpc_id: ResourceId,
        priority: Priority,
        name: Name,
        mutation_protection: MutationProtectionStatus | None = None,
        tags: TagList | None = None,
        **kwargs,
    ) -> AssociateFirewallRuleGroupResponse:
        raise NotImplementedError

    @handler("AssociateResolverEndpointIpAddress")
    def associate_resolver_endpoint_ip_address(
        self,
        context: RequestContext,
        resolver_endpoint_id: ResourceId,
        ip_address: IpAddressUpdate,
        **kwargs,
    ) -> AssociateResolverEndpointIpAddressResponse:
        raise NotImplementedError

    @handler("AssociateResolverQueryLogConfig")
    def associate_resolver_query_log_config(
        self,
        context: RequestContext,
        resolver_query_log_config_id: ResourceId,
        resource_id: ResourceId,
        **kwargs,
    ) -> AssociateResolverQueryLogConfigResponse:
        raise NotImplementedError

    @handler("AssociateResolverRule")
    def associate_resolver_rule(
        self,
        context: RequestContext,
        resolver_rule_id: ResourceId,
        vpc_id: ResourceId,
        name: Name | None = None,
        **kwargs,
    ) -> AssociateResolverRuleResponse:
        raise NotImplementedError

    @handler("CreateFirewallDomainList")
    def create_firewall_domain_list(
        self,
        context: RequestContext,
        creator_request_id: CreatorRequestId,
        name: Name,
        tags: TagList | None = None,
        **kwargs,
    ) -> CreateFirewallDomainListResponse:
        raise NotImplementedError

    @handler("CreateFirewallRule")
    def create_firewall_rule(
        self,
        context: RequestContext,
        creator_request_id: CreatorRequestId,
        firewall_rule_group_id: ResourceId,
        priority: Priority,
        action: Action,
        name: Name,
        firewall_domain_list_id: ResourceId | None = None,
        block_response: BlockResponse | None = None,
        block_override_domain: BlockOverrideDomain | None = None,
        block_override_dns_type: BlockOverrideDnsType | None = None,
        block_override_ttl: BlockOverrideTtl | None = None,
        firewall_domain_redirection_action: FirewallDomainRedirectionAction | None = None,
        qtype: Qtype | None = None,
        dns_threat_protection: DnsThreatProtection | None = None,
        confidence_threshold: ConfidenceThreshold | None = None,
        **kwargs,
    ) -> CreateFirewallRuleResponse:
        raise NotImplementedError

    @handler("CreateFirewallRuleGroup")
    def create_firewall_rule_group(
        self,
        context: RequestContext,
        creator_request_id: CreatorRequestId,
        name: Name,
        tags: TagList | None = None,
        **kwargs,
    ) -> CreateFirewallRuleGroupResponse:
        raise NotImplementedError

    @handler("CreateOutpostResolver")
    def create_outpost_resolver(
        self,
        context: RequestContext,
        creator_request_id: CreatorRequestId,
        name: OutpostResolverName,
        preferred_instance_type: OutpostInstanceType,
        outpost_arn: OutpostArn,
        instance_count: InstanceCount | None = None,
        tags: TagList | None = None,
        **kwargs,
    ) -> CreateOutpostResolverResponse:
        raise NotImplementedError

    @handler("CreateResolverEndpoint")
    def create_resolver_endpoint(
        self,
        context: RequestContext,
        creator_request_id: CreatorRequestId,
        security_group_ids: SecurityGroupIds,
        direction: ResolverEndpointDirection,
        ip_addresses: IpAddressesRequest,
        name: Name | None = None,
        outpost_arn: OutpostArn | None = None,
        preferred_instance_type: OutpostInstanceType | None = None,
        tags: TagList | None = None,
        resolver_endpoint_type: ResolverEndpointType | None = None,
        protocols: ProtocolList | None = None,
        rni_enhanced_metrics_enabled: RniEnhancedMetricsEnabled | None = None,
        target_name_server_metrics_enabled: TargetNameServerMetricsEnabled | None = None,
        **kwargs,
    ) -> CreateResolverEndpointResponse:
        raise NotImplementedError

    @handler("CreateResolverQueryLogConfig")
    def create_resolver_query_log_config(
        self,
        context: RequestContext,
        name: ResolverQueryLogConfigName,
        destination_arn: DestinationArn,
        creator_request_id: CreatorRequestId,
        tags: TagList | None = None,
        **kwargs,
    ) -> CreateResolverQueryLogConfigResponse:
        raise NotImplementedError

    @handler("CreateResolverRule")
    def create_resolver_rule(
        self,
        context: RequestContext,
        creator_request_id: CreatorRequestId,
        rule_type: RuleTypeOption,
        name: Name | None = None,
        domain_name: DomainName | None = None,
        target_ips: TargetList | None = None,
        resolver_endpoint_id: ResourceId | None = None,
        tags: TagList | None = None,
        delegation_record: DelegationRecord | None = None,
        **kwargs,
    ) -> CreateResolverRuleResponse:
        raise NotImplementedError

    @handler("DeleteFirewallDomainList")
    def delete_firewall_domain_list(
        self, context: RequestContext, firewall_domain_list_id: ResourceId, **kwargs
    ) -> DeleteFirewallDomainListResponse:
        raise NotImplementedError

    @handler("DeleteFirewallRule")
    def delete_firewall_rule(
        self,
        context: RequestContext,
        firewall_rule_group_id: ResourceId,
        firewall_domain_list_id: ResourceId | None = None,
        firewall_threat_protection_id: ResourceId | None = None,
        qtype: Qtype | None = None,
        **kwargs,
    ) -> DeleteFirewallRuleResponse:
        raise NotImplementedError

    @handler("DeleteFirewallRuleGroup")
    def delete_firewall_rule_group(
        self, context: RequestContext, firewall_rule_group_id: ResourceId, **kwargs
    ) -> DeleteFirewallRuleGroupResponse:
        raise NotImplementedError

    @handler("DeleteOutpostResolver")
    def delete_outpost_resolver(
        self, context: RequestContext, id: ResourceId, **kwargs
    ) -> DeleteOutpostResolverResponse:
        raise NotImplementedError

    @handler("DeleteResolverEndpoint")
    def delete_resolver_endpoint(
        self, context: RequestContext, resolver_endpoint_id: ResourceId, **kwargs
    ) -> DeleteResolverEndpointResponse:
        raise NotImplementedError

    @handler("DeleteResolverQueryLogConfig")
    def delete_resolver_query_log_config(
        self, context: RequestContext, resolver_query_log_config_id: ResourceId, **kwargs
    ) -> DeleteResolverQueryLogConfigResponse:
        raise NotImplementedError

    @handler("DeleteResolverRule")
    def delete_resolver_rule(
        self, context: RequestContext, resolver_rule_id: ResourceId, **kwargs
    ) -> DeleteResolverRuleResponse:
        raise NotImplementedError

    @handler("DisassociateFirewallRuleGroup")
    def disassociate_firewall_rule_group(
        self, context: RequestContext, firewall_rule_group_association_id: ResourceId, **kwargs
    ) -> DisassociateFirewallRuleGroupResponse:
        raise NotImplementedError

    @handler("DisassociateResolverEndpointIpAddress")
    def disassociate_resolver_endpoint_ip_address(
        self,
        context: RequestContext,
        resolver_endpoint_id: ResourceId,
        ip_address: IpAddressUpdate,
        **kwargs,
    ) -> DisassociateResolverEndpointIpAddressResponse:
        raise NotImplementedError

    @handler("DisassociateResolverQueryLogConfig")
    def disassociate_resolver_query_log_config(
        self,
        context: RequestContext,
        resolver_query_log_config_id: ResourceId,
        resource_id: ResourceId,
        **kwargs,
    ) -> DisassociateResolverQueryLogConfigResponse:
        raise NotImplementedError

    @handler("DisassociateResolverRule")
    def disassociate_resolver_rule(
        self, context: RequestContext, vpc_id: ResourceId, resolver_rule_id: ResourceId, **kwargs
    ) -> DisassociateResolverRuleResponse:
        raise NotImplementedError

    @handler("GetFirewallConfig")
    def get_firewall_config(
        self, context: RequestContext, resource_id: ResourceId, **kwargs
    ) -> GetFirewallConfigResponse:
        raise NotImplementedError

    @handler("GetFirewallDomainList")
    def get_firewall_domain_list(
        self, context: RequestContext, firewall_domain_list_id: ResourceId, **kwargs
    ) -> GetFirewallDomainListResponse:
        raise NotImplementedError

    @handler("GetFirewallRuleGroup")
    def get_firewall_rule_group(
        self, context: RequestContext, firewall_rule_group_id: ResourceId, **kwargs
    ) -> GetFirewallRuleGroupResponse:
        raise NotImplementedError

    @handler("GetFirewallRuleGroupAssociation")
    def get_firewall_rule_group_association(
        self, context: RequestContext, firewall_rule_group_association_id: ResourceId, **kwargs
    ) -> GetFirewallRuleGroupAssociationResponse:
        raise NotImplementedError

    @handler("GetFirewallRuleGroupPolicy")
    def get_firewall_rule_group_policy(
        self, context: RequestContext, arn: Arn, **kwargs
    ) -> GetFirewallRuleGroupPolicyResponse:
        raise NotImplementedError

    @handler("GetOutpostResolver")
    def get_outpost_resolver(
        self, context: RequestContext, id: ResourceId, **kwargs
    ) -> GetOutpostResolverResponse:
        raise NotImplementedError

    @handler("GetResolverConfig")
    def get_resolver_config(
        self, context: RequestContext, resource_id: ResourceId, **kwargs
    ) -> GetResolverConfigResponse:
        raise NotImplementedError

    @handler("GetResolverDnssecConfig")
    def get_resolver_dnssec_config(
        self, context: RequestContext, resource_id: ResourceId, **kwargs
    ) -> GetResolverDnssecConfigResponse:
        raise NotImplementedError

    @handler("GetResolverEndpoint")
    def get_resolver_endpoint(
        self, context: RequestContext, resolver_endpoint_id: ResourceId, **kwargs
    ) -> GetResolverEndpointResponse:
        raise NotImplementedError

    @handler("GetResolverQueryLogConfig")
    def get_resolver_query_log_config(
        self, context: RequestContext, resolver_query_log_config_id: ResourceId, **kwargs
    ) -> GetResolverQueryLogConfigResponse:
        raise NotImplementedError

    @handler("GetResolverQueryLogConfigAssociation")
    def get_resolver_query_log_config_association(
        self,
        context: RequestContext,
        resolver_query_log_config_association_id: ResourceId,
        **kwargs,
    ) -> GetResolverQueryLogConfigAssociationResponse:
        raise NotImplementedError

    @handler("GetResolverQueryLogConfigPolicy")
    def get_resolver_query_log_config_policy(
        self, context: RequestContext, arn: Arn, **kwargs
    ) -> GetResolverQueryLogConfigPolicyResponse:
        raise NotImplementedError

    @handler("GetResolverRule")
    def get_resolver_rule(
        self, context: RequestContext, resolver_rule_id: ResourceId, **kwargs
    ) -> GetResolverRuleResponse:
        raise NotImplementedError

    @handler("GetResolverRuleAssociation")
    def get_resolver_rule_association(
        self, context: RequestContext, resolver_rule_association_id: ResourceId, **kwargs
    ) -> GetResolverRuleAssociationResponse:
        raise NotImplementedError

    @handler("GetResolverRulePolicy")
    def get_resolver_rule_policy(
        self, context: RequestContext, arn: Arn, **kwargs
    ) -> GetResolverRulePolicyResponse:
        raise NotImplementedError

    @handler("ImportFirewallDomains")
    def import_firewall_domains(
        self,
        context: RequestContext,
        firewall_domain_list_id: ResourceId,
        operation: FirewallDomainImportOperation,
        domain_file_url: DomainListFileUrl,
        **kwargs,
    ) -> ImportFirewallDomainsResponse:
        raise NotImplementedError

    @handler("ListFirewallConfigs")
    def list_firewall_configs(
        self,
        context: RequestContext,
        max_results: ListFirewallConfigsMaxResult | None = None,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> ListFirewallConfigsResponse:
        raise NotImplementedError

    @handler("ListFirewallDomainLists")
    def list_firewall_domain_lists(
        self,
        context: RequestContext,
        max_results: MaxResults | None = None,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> ListFirewallDomainListsResponse:
        raise NotImplementedError

    @handler("ListFirewallDomains")
    def list_firewall_domains(
        self,
        context: RequestContext,
        firewall_domain_list_id: ResourceId,
        max_results: ListDomainMaxResults | None = None,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> ListFirewallDomainsResponse:
        raise NotImplementedError

    @handler("ListFirewallRuleGroupAssociations")
    def list_firewall_rule_group_associations(
        self,
        context: RequestContext,
        firewall_rule_group_id: ResourceId | None = None,
        vpc_id: ResourceId | None = None,
        priority: Priority | None = None,
        status: FirewallRuleGroupAssociationStatus | None = None,
        max_results: MaxResults | None = None,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> ListFirewallRuleGroupAssociationsResponse:
        raise NotImplementedError

    @handler("ListFirewallRuleGroups")
    def list_firewall_rule_groups(
        self,
        context: RequestContext,
        max_results: MaxResults | None = None,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> ListFirewallRuleGroupsResponse:
        raise NotImplementedError

    @handler("ListFirewallRules")
    def list_firewall_rules(
        self,
        context: RequestContext,
        firewall_rule_group_id: ResourceId,
        priority: Priority | None = None,
        action: Action | None = None,
        max_results: MaxResults | None = None,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> ListFirewallRulesResponse:
        raise NotImplementedError

    @handler("ListOutpostResolvers")
    def list_outpost_resolvers(
        self,
        context: RequestContext,
        outpost_arn: OutpostArn | None = None,
        max_results: MaxResults | None = None,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> ListOutpostResolversResponse:
        raise NotImplementedError

    @handler("ListResolverConfigs")
    def list_resolver_configs(
        self,
        context: RequestContext,
        max_results: ListResolverConfigsMaxResult | None = None,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> ListResolverConfigsResponse:
        raise NotImplementedError

    @handler("ListResolverDnssecConfigs")
    def list_resolver_dnssec_configs(
        self,
        context: RequestContext,
        max_results: MaxResults | None = None,
        next_token: NextToken | None = None,
        filters: Filters | None = None,
        **kwargs,
    ) -> ListResolverDnssecConfigsResponse:
        raise NotImplementedError

    @handler("ListResolverEndpointIpAddresses")
    def list_resolver_endpoint_ip_addresses(
        self,
        context: RequestContext,
        resolver_endpoint_id: ResourceId,
        max_results: MaxResults | None = None,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> ListResolverEndpointIpAddressesResponse:
        raise NotImplementedError

    @handler("ListResolverEndpoints")
    def list_resolver_endpoints(
        self,
        context: RequestContext,
        max_results: MaxResults | None = None,
        next_token: NextToken | None = None,
        filters: Filters | None = None,
        **kwargs,
    ) -> ListResolverEndpointsResponse:
        raise NotImplementedError

    @handler("ListResolverQueryLogConfigAssociations")
    def list_resolver_query_log_config_associations(
        self,
        context: RequestContext,
        max_results: MaxResults | None = None,
        next_token: NextToken | None = None,
        filters: Filters | None = None,
        sort_by: SortByKey | None = None,
        sort_order: SortOrder | None = None,
        **kwargs,
    ) -> ListResolverQueryLogConfigAssociationsResponse:
        raise NotImplementedError

    @handler("ListResolverQueryLogConfigs")
    def list_resolver_query_log_configs(
        self,
        context: RequestContext,
        max_results: MaxResults | None = None,
        next_token: NextToken | None = None,
        filters: Filters | None = None,
        sort_by: SortByKey | None = None,
        sort_order: SortOrder | None = None,
        **kwargs,
    ) -> ListResolverQueryLogConfigsResponse:
        raise NotImplementedError

    @handler("ListResolverRuleAssociations")
    def list_resolver_rule_associations(
        self,
        context: RequestContext,
        max_results: MaxResults | None = None,
        next_token: NextToken | None = None,
        filters: Filters | None = None,
        **kwargs,
    ) -> ListResolverRuleAssociationsResponse:
        raise NotImplementedError

    @handler("ListResolverRules")
    def list_resolver_rules(
        self,
        context: RequestContext,
        max_results: MaxResults | None = None,
        next_token: NextToken | None = None,
        filters: Filters | None = None,
        **kwargs,
    ) -> ListResolverRulesResponse:
        raise NotImplementedError

    @handler("ListTagsForResource")
    def list_tags_for_resource(
        self,
        context: RequestContext,
        resource_arn: Arn,
        max_results: MaxResults | None = None,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> ListTagsForResourceResponse:
        raise NotImplementedError

    @handler("PutFirewallRuleGroupPolicy")
    def put_firewall_rule_group_policy(
        self,
        context: RequestContext,
        arn: Arn,
        firewall_rule_group_policy: FirewallRuleGroupPolicy,
        **kwargs,
    ) -> PutFirewallRuleGroupPolicyResponse:
        raise NotImplementedError

    @handler("PutResolverQueryLogConfigPolicy")
    def put_resolver_query_log_config_policy(
        self,
        context: RequestContext,
        arn: Arn,
        resolver_query_log_config_policy: ResolverQueryLogConfigPolicy,
        **kwargs,
    ) -> PutResolverQueryLogConfigPolicyResponse:
        raise NotImplementedError

    @handler("PutResolverRulePolicy")
    def put_resolver_rule_policy(
        self, context: RequestContext, arn: Arn, resolver_rule_policy: ResolverRulePolicy, **kwargs
    ) -> PutResolverRulePolicyResponse:
        raise NotImplementedError

    @handler("TagResource")
    def tag_resource(
        self, context: RequestContext, resource_arn: Arn, tags: TagList, **kwargs
    ) -> TagResourceResponse:
        raise NotImplementedError

    @handler("UntagResource")
    def untag_resource(
        self, context: RequestContext, resource_arn: Arn, tag_keys: TagKeyList, **kwargs
    ) -> UntagResourceResponse:
        raise NotImplementedError

    @handler("UpdateFirewallConfig")
    def update_firewall_config(
        self,
        context: RequestContext,
        resource_id: ResourceId,
        firewall_fail_open: FirewallFailOpenStatus,
        **kwargs,
    ) -> UpdateFirewallConfigResponse:
        raise NotImplementedError

    @handler("UpdateFirewallDomains")
    def update_firewall_domains(
        self,
        context: RequestContext,
        firewall_domain_list_id: ResourceId,
        operation: FirewallDomainUpdateOperation,
        domains: FirewallDomains,
        **kwargs,
    ) -> UpdateFirewallDomainsResponse:
        raise NotImplementedError

    @handler("UpdateFirewallRule")
    def update_firewall_rule(
        self,
        context: RequestContext,
        firewall_rule_group_id: ResourceId,
        firewall_domain_list_id: ResourceId | None = None,
        firewall_threat_protection_id: ResourceId | None = None,
        priority: Priority | None = None,
        action: Action | None = None,
        block_response: BlockResponse | None = None,
        block_override_domain: BlockOverrideDomain | None = None,
        block_override_dns_type: BlockOverrideDnsType | None = None,
        block_override_ttl: BlockOverrideTtl | None = None,
        name: Name | None = None,
        firewall_domain_redirection_action: FirewallDomainRedirectionAction | None = None,
        qtype: Qtype | None = None,
        dns_threat_protection: DnsThreatProtection | None = None,
        confidence_threshold: ConfidenceThreshold | None = None,
        **kwargs,
    ) -> UpdateFirewallRuleResponse:
        raise NotImplementedError

    @handler("UpdateFirewallRuleGroupAssociation")
    def update_firewall_rule_group_association(
        self,
        context: RequestContext,
        firewall_rule_group_association_id: ResourceId,
        priority: Priority | None = None,
        mutation_protection: MutationProtectionStatus | None = None,
        name: Name | None = None,
        **kwargs,
    ) -> UpdateFirewallRuleGroupAssociationResponse:
        raise NotImplementedError

    @handler("UpdateOutpostResolver")
    def update_outpost_resolver(
        self,
        context: RequestContext,
        id: ResourceId,
        name: OutpostResolverName | None = None,
        instance_count: InstanceCount | None = None,
        preferred_instance_type: OutpostInstanceType | None = None,
        **kwargs,
    ) -> UpdateOutpostResolverResponse:
        raise NotImplementedError

    @handler("UpdateResolverConfig")
    def update_resolver_config(
        self,
        context: RequestContext,
        resource_id: ResourceId,
        autodefined_reverse_flag: AutodefinedReverseFlag,
        **kwargs,
    ) -> UpdateResolverConfigResponse:
        raise NotImplementedError

    @handler("UpdateResolverDnssecConfig")
    def update_resolver_dnssec_config(
        self, context: RequestContext, resource_id: ResourceId, validation: Validation, **kwargs
    ) -> UpdateResolverDnssecConfigResponse:
        raise NotImplementedError

    @handler("UpdateResolverEndpoint")
    def update_resolver_endpoint(
        self,
        context: RequestContext,
        resolver_endpoint_id: ResourceId,
        name: Name | None = None,
        resolver_endpoint_type: ResolverEndpointType | None = None,
        update_ip_addresses: UpdateIpAddresses | None = None,
        protocols: ProtocolList | None = None,
        rni_enhanced_metrics_enabled: RniEnhancedMetricsEnabled | None = None,
        target_name_server_metrics_enabled: TargetNameServerMetricsEnabled | None = None,
        **kwargs,
    ) -> UpdateResolverEndpointResponse:
        raise NotImplementedError

    @handler("UpdateResolverRule")
    def update_resolver_rule(
        self,
        context: RequestContext,
        resolver_rule_id: ResourceId,
        config: ResolverRuleConfig,
        **kwargs,
    ) -> UpdateResolverRuleResponse:
        raise NotImplementedError
