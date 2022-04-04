import sys
from typing import List, Optional

if sys.version_info >= (3, 8):
    from typing import TypedDict
else:
    from typing_extensions import TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

AccountId = str
Arn = str
BlockOverrideDomain = str
BlockOverrideTtl = int
Boolean = bool
Count = int
CreatorRequestId = str
DestinationArn = str
DomainListFileUrl = str
DomainName = str
ExceptionMessage = str
FilterName = str
FilterValue = str
FirewallDomainName = str
FirewallRuleGroupPolicy = str
Ip = str
IpAddressCount = int
ListDomainMaxResults = int
ListFirewallConfigsMaxResult = int
ListResolverConfigsMaxResult = int
MaxResults = int
Name = str
NextToken = str
Port = int
Priority = int
ResolverQueryLogConfigAssociationErrorMessage = str
ResolverQueryLogConfigName = str
ResolverQueryLogConfigPolicy = str
ResolverRulePolicy = str
ResourceId = str
Rfc3339TimeString = str
ServicePrinciple = str
SortByKey = str
StatusMessage = str
String = str
SubnetId = str
TagKey = str
TagValue = str
Unsigned = int


class Action(str):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    ALERT = "ALERT"


class AutodefinedReverseFlag(str):
    ENABLE = "ENABLE"
    DISABLE = "DISABLE"


class BlockOverrideDnsType(str):
    CNAME = "CNAME"


class BlockResponse(str):
    NODATA = "NODATA"
    NXDOMAIN = "NXDOMAIN"
    OVERRIDE = "OVERRIDE"


class FirewallDomainImportOperation(str):
    REPLACE = "REPLACE"


class FirewallDomainListStatus(str):
    COMPLETE = "COMPLETE"
    COMPLETE_IMPORT_FAILED = "COMPLETE_IMPORT_FAILED"
    IMPORTING = "IMPORTING"
    DELETING = "DELETING"
    UPDATING = "UPDATING"


class FirewallDomainUpdateOperation(str):
    ADD = "ADD"
    REMOVE = "REMOVE"
    REPLACE = "REPLACE"


class FirewallFailOpenStatus(str):
    ENABLED = "ENABLED"
    DISABLED = "DISABLED"


class FirewallRuleGroupAssociationStatus(str):
    COMPLETE = "COMPLETE"
    DELETING = "DELETING"
    UPDATING = "UPDATING"


class FirewallRuleGroupStatus(str):
    COMPLETE = "COMPLETE"
    DELETING = "DELETING"
    UPDATING = "UPDATING"


class IpAddressStatus(str):
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


class MutationProtectionStatus(str):
    ENABLED = "ENABLED"
    DISABLED = "DISABLED"


class ResolverAutodefinedReverseStatus(str):
    ENABLING = "ENABLING"
    ENABLED = "ENABLED"
    DISABLING = "DISABLING"
    DISABLED = "DISABLED"


class ResolverDNSSECValidationStatus(str):
    ENABLING = "ENABLING"
    ENABLED = "ENABLED"
    DISABLING = "DISABLING"
    DISABLED = "DISABLED"


class ResolverEndpointDirection(str):
    INBOUND = "INBOUND"
    OUTBOUND = "OUTBOUND"


class ResolverEndpointStatus(str):
    CREATING = "CREATING"
    OPERATIONAL = "OPERATIONAL"
    UPDATING = "UPDATING"
    AUTO_RECOVERING = "AUTO_RECOVERING"
    ACTION_NEEDED = "ACTION_NEEDED"
    DELETING = "DELETING"


class ResolverQueryLogConfigAssociationError(str):
    NONE = "NONE"
    DESTINATION_NOT_FOUND = "DESTINATION_NOT_FOUND"
    ACCESS_DENIED = "ACCESS_DENIED"
    INTERNAL_SERVICE_ERROR = "INTERNAL_SERVICE_ERROR"


class ResolverQueryLogConfigAssociationStatus(str):
    CREATING = "CREATING"
    ACTIVE = "ACTIVE"
    ACTION_NEEDED = "ACTION_NEEDED"
    DELETING = "DELETING"
    FAILED = "FAILED"


class ResolverQueryLogConfigStatus(str):
    CREATING = "CREATING"
    CREATED = "CREATED"
    DELETING = "DELETING"
    FAILED = "FAILED"


class ResolverRuleAssociationStatus(str):
    CREATING = "CREATING"
    COMPLETE = "COMPLETE"
    DELETING = "DELETING"
    FAILED = "FAILED"
    OVERRIDDEN = "OVERRIDDEN"


class ResolverRuleStatus(str):
    COMPLETE = "COMPLETE"
    DELETING = "DELETING"
    UPDATING = "UPDATING"
    FAILED = "FAILED"


class RuleTypeOption(str):
    FORWARD = "FORWARD"
    SYSTEM = "SYSTEM"
    RECURSIVE = "RECURSIVE"


class ShareStatus(str):
    NOT_SHARED = "NOT_SHARED"
    SHARED_WITH_ME = "SHARED_WITH_ME"
    SHARED_BY_ME = "SHARED_BY_ME"


class SortOrder(str):
    ASCENDING = "ASCENDING"
    DESCENDING = "DESCENDING"


class Validation(str):
    ENABLE = "ENABLE"
    DISABLE = "DISABLE"


class AccessDeniedException(ServiceException):
    Message: Optional[ExceptionMessage]


class ConflictException(ServiceException):
    Message: Optional[ExceptionMessage]


class InternalServiceErrorException(ServiceException):
    Message: Optional[ExceptionMessage]


class InvalidNextTokenException(ServiceException):
    Message: Optional[String]


class InvalidParameterException(ServiceException):
    Message: ExceptionMessage
    FieldName: Optional[String]


class InvalidPolicyDocument(ServiceException):
    Message: Optional[ExceptionMessage]


class InvalidRequestException(ServiceException):
    Message: Optional[ExceptionMessage]


class InvalidTagException(ServiceException):
    Message: Optional[ExceptionMessage]


class LimitExceededException(ServiceException):
    Message: Optional[String]
    ResourceType: Optional[String]


class ResourceExistsException(ServiceException):
    Message: Optional[String]
    ResourceType: Optional[String]


class ResourceInUseException(ServiceException):
    Message: Optional[String]
    ResourceType: Optional[String]


class ResourceNotFoundException(ServiceException):
    Message: Optional[String]
    ResourceType: Optional[String]


class ResourceUnavailableException(ServiceException):
    Message: Optional[String]
    ResourceType: Optional[String]


class ThrottlingException(ServiceException):
    Message: Optional[ExceptionMessage]


class UnknownResourceException(ServiceException):
    Message: Optional[ExceptionMessage]


class ValidationException(ServiceException):
    Message: Optional[ExceptionMessage]


class Tag(TypedDict, total=False):
    Key: TagKey
    Value: TagValue


TagList = List[Tag]


class AssociateFirewallRuleGroupRequest(ServiceRequest):
    CreatorRequestId: CreatorRequestId
    FirewallRuleGroupId: ResourceId
    VpcId: ResourceId
    Priority: Priority
    Name: Name
    MutationProtection: Optional[MutationProtectionStatus]
    Tags: Optional[TagList]


class FirewallRuleGroupAssociation(TypedDict, total=False):
    Id: Optional[ResourceId]
    Arn: Optional[Arn]
    FirewallRuleGroupId: Optional[ResourceId]
    VpcId: Optional[ResourceId]
    Name: Optional[Name]
    Priority: Optional[Priority]
    MutationProtection: Optional[MutationProtectionStatus]
    ManagedOwnerName: Optional[ServicePrinciple]
    Status: Optional[FirewallRuleGroupAssociationStatus]
    StatusMessage: Optional[StatusMessage]
    CreatorRequestId: Optional[CreatorRequestId]
    CreationTime: Optional[Rfc3339TimeString]
    ModificationTime: Optional[Rfc3339TimeString]


class AssociateFirewallRuleGroupResponse(TypedDict, total=False):
    FirewallRuleGroupAssociation: Optional[FirewallRuleGroupAssociation]


class IpAddressUpdate(TypedDict, total=False):
    IpId: Optional[ResourceId]
    SubnetId: Optional[SubnetId]
    Ip: Optional[Ip]


class AssociateResolverEndpointIpAddressRequest(ServiceRequest):
    ResolverEndpointId: ResourceId
    IpAddress: IpAddressUpdate


SecurityGroupIds = List[ResourceId]


class ResolverEndpoint(TypedDict, total=False):
    Id: Optional[ResourceId]
    CreatorRequestId: Optional[CreatorRequestId]
    Arn: Optional[Arn]
    Name: Optional[Name]
    SecurityGroupIds: Optional[SecurityGroupIds]
    Direction: Optional[ResolverEndpointDirection]
    IpAddressCount: Optional[IpAddressCount]
    HostVPCId: Optional[ResourceId]
    Status: Optional[ResolverEndpointStatus]
    StatusMessage: Optional[StatusMessage]
    CreationTime: Optional[Rfc3339TimeString]
    ModificationTime: Optional[Rfc3339TimeString]


class AssociateResolverEndpointIpAddressResponse(TypedDict, total=False):
    ResolverEndpoint: Optional[ResolverEndpoint]


class AssociateResolverQueryLogConfigRequest(ServiceRequest):
    ResolverQueryLogConfigId: ResourceId
    ResourceId: ResourceId


class ResolverQueryLogConfigAssociation(TypedDict, total=False):
    Id: Optional[ResourceId]
    ResolverQueryLogConfigId: Optional[ResourceId]
    ResourceId: Optional[ResourceId]
    Status: Optional[ResolverQueryLogConfigAssociationStatus]
    Error: Optional[ResolverQueryLogConfigAssociationError]
    ErrorMessage: Optional[ResolverQueryLogConfigAssociationErrorMessage]
    CreationTime: Optional[Rfc3339TimeString]


class AssociateResolverQueryLogConfigResponse(TypedDict, total=False):
    ResolverQueryLogConfigAssociation: Optional[ResolverQueryLogConfigAssociation]


class AssociateResolverRuleRequest(ServiceRequest):
    ResolverRuleId: ResourceId
    Name: Optional[Name]
    VPCId: ResourceId


class ResolverRuleAssociation(TypedDict, total=False):
    Id: Optional[ResourceId]
    ResolverRuleId: Optional[ResourceId]
    Name: Optional[Name]
    VPCId: Optional[ResourceId]
    Status: Optional[ResolverRuleAssociationStatus]
    StatusMessage: Optional[StatusMessage]


class AssociateResolverRuleResponse(TypedDict, total=False):
    ResolverRuleAssociation: Optional[ResolverRuleAssociation]


class CreateFirewallDomainListRequest(ServiceRequest):
    CreatorRequestId: CreatorRequestId
    Name: Name
    Tags: Optional[TagList]


class FirewallDomainList(TypedDict, total=False):
    Id: Optional[ResourceId]
    Arn: Optional[Arn]
    Name: Optional[Name]
    DomainCount: Optional[Unsigned]
    Status: Optional[FirewallDomainListStatus]
    StatusMessage: Optional[StatusMessage]
    ManagedOwnerName: Optional[ServicePrinciple]
    CreatorRequestId: Optional[CreatorRequestId]
    CreationTime: Optional[Rfc3339TimeString]
    ModificationTime: Optional[Rfc3339TimeString]


class CreateFirewallDomainListResponse(TypedDict, total=False):
    FirewallDomainList: Optional[FirewallDomainList]


class CreateFirewallRuleGroupRequest(ServiceRequest):
    CreatorRequestId: CreatorRequestId
    Name: Name
    Tags: Optional[TagList]


class FirewallRuleGroup(TypedDict, total=False):
    Id: Optional[ResourceId]
    Arn: Optional[Arn]
    Name: Optional[Name]
    RuleCount: Optional[Unsigned]
    Status: Optional[FirewallRuleGroupStatus]
    StatusMessage: Optional[StatusMessage]
    OwnerId: Optional[AccountId]
    CreatorRequestId: Optional[CreatorRequestId]
    ShareStatus: Optional[ShareStatus]
    CreationTime: Optional[Rfc3339TimeString]
    ModificationTime: Optional[Rfc3339TimeString]


class CreateFirewallRuleGroupResponse(TypedDict, total=False):
    FirewallRuleGroup: Optional[FirewallRuleGroup]


class CreateFirewallRuleRequest(ServiceRequest):
    CreatorRequestId: CreatorRequestId
    FirewallRuleGroupId: ResourceId
    FirewallDomainListId: ResourceId
    Priority: Priority
    Action: Action
    BlockResponse: Optional[BlockResponse]
    BlockOverrideDomain: Optional[BlockOverrideDomain]
    BlockOverrideDnsType: Optional[BlockOverrideDnsType]
    BlockOverrideTtl: Optional[BlockOverrideTtl]
    Name: Name


class FirewallRule(TypedDict, total=False):
    FirewallRuleGroupId: Optional[ResourceId]
    FirewallDomainListId: Optional[ResourceId]
    Name: Optional[Name]
    Priority: Optional[Priority]
    Action: Optional[Action]
    BlockResponse: Optional[BlockResponse]
    BlockOverrideDomain: Optional[BlockOverrideDomain]
    BlockOverrideDnsType: Optional[BlockOverrideDnsType]
    BlockOverrideTtl: Optional[Unsigned]
    CreatorRequestId: Optional[CreatorRequestId]
    CreationTime: Optional[Rfc3339TimeString]
    ModificationTime: Optional[Rfc3339TimeString]


class CreateFirewallRuleResponse(TypedDict, total=False):
    FirewallRule: Optional[FirewallRule]


class IpAddressRequest(TypedDict, total=False):
    SubnetId: SubnetId
    Ip: Optional[Ip]


IpAddressesRequest = List[IpAddressRequest]


class CreateResolverEndpointRequest(ServiceRequest):
    CreatorRequestId: CreatorRequestId
    Name: Optional[Name]
    SecurityGroupIds: SecurityGroupIds
    Direction: ResolverEndpointDirection
    IpAddresses: IpAddressesRequest
    Tags: Optional[TagList]


class CreateResolverEndpointResponse(TypedDict, total=False):
    ResolverEndpoint: Optional[ResolverEndpoint]


class CreateResolverQueryLogConfigRequest(ServiceRequest):
    Name: ResolverQueryLogConfigName
    DestinationArn: DestinationArn
    CreatorRequestId: CreatorRequestId
    Tags: Optional[TagList]


class ResolverQueryLogConfig(TypedDict, total=False):
    Id: Optional[ResourceId]
    OwnerId: Optional[AccountId]
    Status: Optional[ResolverQueryLogConfigStatus]
    ShareStatus: Optional[ShareStatus]
    AssociationCount: Optional[Count]
    Arn: Optional[Arn]
    Name: Optional[ResolverQueryLogConfigName]
    DestinationArn: Optional[DestinationArn]
    CreatorRequestId: Optional[CreatorRequestId]
    CreationTime: Optional[Rfc3339TimeString]


class CreateResolverQueryLogConfigResponse(TypedDict, total=False):
    ResolverQueryLogConfig: Optional[ResolverQueryLogConfig]


class TargetAddress(TypedDict, total=False):
    Ip: Ip
    Port: Optional[Port]


TargetList = List[TargetAddress]


class CreateResolverRuleRequest(ServiceRequest):
    CreatorRequestId: CreatorRequestId
    Name: Optional[Name]
    RuleType: RuleTypeOption
    DomainName: DomainName
    TargetIps: Optional[TargetList]
    ResolverEndpointId: Optional[ResourceId]
    Tags: Optional[TagList]


class ResolverRule(TypedDict, total=False):
    Id: Optional[ResourceId]
    CreatorRequestId: Optional[CreatorRequestId]
    Arn: Optional[Arn]
    DomainName: Optional[DomainName]
    Status: Optional[ResolverRuleStatus]
    StatusMessage: Optional[StatusMessage]
    RuleType: Optional[RuleTypeOption]
    Name: Optional[Name]
    TargetIps: Optional[TargetList]
    ResolverEndpointId: Optional[ResourceId]
    OwnerId: Optional[AccountId]
    ShareStatus: Optional[ShareStatus]
    CreationTime: Optional[Rfc3339TimeString]
    ModificationTime: Optional[Rfc3339TimeString]


class CreateResolverRuleResponse(TypedDict, total=False):
    ResolverRule: Optional[ResolverRule]


class DeleteFirewallDomainListRequest(ServiceRequest):
    FirewallDomainListId: ResourceId


class DeleteFirewallDomainListResponse(TypedDict, total=False):
    FirewallDomainList: Optional[FirewallDomainList]


class DeleteFirewallRuleGroupRequest(ServiceRequest):
    FirewallRuleGroupId: ResourceId


class DeleteFirewallRuleGroupResponse(TypedDict, total=False):
    FirewallRuleGroup: Optional[FirewallRuleGroup]


class DeleteFirewallRuleRequest(ServiceRequest):
    FirewallRuleGroupId: ResourceId
    FirewallDomainListId: ResourceId


class DeleteFirewallRuleResponse(TypedDict, total=False):
    FirewallRule: Optional[FirewallRule]


class DeleteResolverEndpointRequest(ServiceRequest):
    ResolverEndpointId: ResourceId


class DeleteResolverEndpointResponse(TypedDict, total=False):
    ResolverEndpoint: Optional[ResolverEndpoint]


class DeleteResolverQueryLogConfigRequest(ServiceRequest):
    ResolverQueryLogConfigId: ResourceId


class DeleteResolverQueryLogConfigResponse(TypedDict, total=False):
    ResolverQueryLogConfig: Optional[ResolverQueryLogConfig]


class DeleteResolverRuleRequest(ServiceRequest):
    ResolverRuleId: ResourceId


class DeleteResolverRuleResponse(TypedDict, total=False):
    ResolverRule: Optional[ResolverRule]


class DisassociateFirewallRuleGroupRequest(ServiceRequest):
    FirewallRuleGroupAssociationId: ResourceId


class DisassociateFirewallRuleGroupResponse(TypedDict, total=False):
    FirewallRuleGroupAssociation: Optional[FirewallRuleGroupAssociation]


class DisassociateResolverEndpointIpAddressRequest(ServiceRequest):
    ResolverEndpointId: ResourceId
    IpAddress: IpAddressUpdate


class DisassociateResolverEndpointIpAddressResponse(TypedDict, total=False):
    ResolverEndpoint: Optional[ResolverEndpoint]


class DisassociateResolverQueryLogConfigRequest(ServiceRequest):
    ResolverQueryLogConfigId: ResourceId
    ResourceId: ResourceId


class DisassociateResolverQueryLogConfigResponse(TypedDict, total=False):
    ResolverQueryLogConfigAssociation: Optional[ResolverQueryLogConfigAssociation]


class DisassociateResolverRuleRequest(ServiceRequest):
    VPCId: ResourceId
    ResolverRuleId: ResourceId


class DisassociateResolverRuleResponse(TypedDict, total=False):
    ResolverRuleAssociation: Optional[ResolverRuleAssociation]


FilterValues = List[FilterValue]


class Filter(TypedDict, total=False):
    Name: Optional[FilterName]
    Values: Optional[FilterValues]


Filters = List[Filter]


class FirewallConfig(TypedDict, total=False):
    Id: Optional[ResourceId]
    ResourceId: Optional[ResourceId]
    OwnerId: Optional[AccountId]
    FirewallFailOpen: Optional[FirewallFailOpenStatus]


FirewallConfigList = List[FirewallConfig]


class FirewallDomainListMetadata(TypedDict, total=False):
    Id: Optional[ResourceId]
    Arn: Optional[Arn]
    Name: Optional[Name]
    CreatorRequestId: Optional[CreatorRequestId]
    ManagedOwnerName: Optional[ServicePrinciple]


FirewallDomainListMetadataList = List[FirewallDomainListMetadata]
FirewallDomains = List[FirewallDomainName]
FirewallRuleGroupAssociations = List[FirewallRuleGroupAssociation]


class FirewallRuleGroupMetadata(TypedDict, total=False):
    Id: Optional[ResourceId]
    Arn: Optional[Arn]
    Name: Optional[Name]
    OwnerId: Optional[AccountId]
    CreatorRequestId: Optional[CreatorRequestId]
    ShareStatus: Optional[ShareStatus]


FirewallRuleGroupMetadataList = List[FirewallRuleGroupMetadata]
FirewallRules = List[FirewallRule]


class GetFirewallConfigRequest(ServiceRequest):
    ResourceId: ResourceId


class GetFirewallConfigResponse(TypedDict, total=False):
    FirewallConfig: Optional[FirewallConfig]


class GetFirewallDomainListRequest(ServiceRequest):
    FirewallDomainListId: ResourceId


class GetFirewallDomainListResponse(TypedDict, total=False):
    FirewallDomainList: Optional[FirewallDomainList]


class GetFirewallRuleGroupAssociationRequest(ServiceRequest):
    FirewallRuleGroupAssociationId: ResourceId


class GetFirewallRuleGroupAssociationResponse(TypedDict, total=False):
    FirewallRuleGroupAssociation: Optional[FirewallRuleGroupAssociation]


class GetFirewallRuleGroupPolicyRequest(ServiceRequest):
    Arn: Arn


class GetFirewallRuleGroupPolicyResponse(TypedDict, total=False):
    FirewallRuleGroupPolicy: Optional[FirewallRuleGroupPolicy]


class GetFirewallRuleGroupRequest(ServiceRequest):
    FirewallRuleGroupId: ResourceId


class GetFirewallRuleGroupResponse(TypedDict, total=False):
    FirewallRuleGroup: Optional[FirewallRuleGroup]


class GetResolverConfigRequest(ServiceRequest):
    ResourceId: ResourceId


class ResolverConfig(TypedDict, total=False):
    Id: Optional[ResourceId]
    ResourceId: Optional[ResourceId]
    OwnerId: Optional[AccountId]
    AutodefinedReverse: Optional[ResolverAutodefinedReverseStatus]


class GetResolverConfigResponse(TypedDict, total=False):
    ResolverConfig: Optional[ResolverConfig]


class GetResolverDnssecConfigRequest(ServiceRequest):
    ResourceId: ResourceId


class ResolverDnssecConfig(TypedDict, total=False):
    Id: Optional[ResourceId]
    OwnerId: Optional[AccountId]
    ResourceId: Optional[ResourceId]
    ValidationStatus: Optional[ResolverDNSSECValidationStatus]


class GetResolverDnssecConfigResponse(TypedDict, total=False):
    ResolverDNSSECConfig: Optional[ResolverDnssecConfig]


class GetResolverEndpointRequest(ServiceRequest):
    ResolverEndpointId: ResourceId


class GetResolverEndpointResponse(TypedDict, total=False):
    ResolverEndpoint: Optional[ResolverEndpoint]


class GetResolverQueryLogConfigAssociationRequest(ServiceRequest):
    ResolverQueryLogConfigAssociationId: ResourceId


class GetResolverQueryLogConfigAssociationResponse(TypedDict, total=False):
    ResolverQueryLogConfigAssociation: Optional[ResolverQueryLogConfigAssociation]


class GetResolverQueryLogConfigPolicyRequest(ServiceRequest):
    Arn: Arn


class GetResolverQueryLogConfigPolicyResponse(TypedDict, total=False):
    ResolverQueryLogConfigPolicy: Optional[ResolverQueryLogConfigPolicy]


class GetResolverQueryLogConfigRequest(ServiceRequest):
    ResolverQueryLogConfigId: ResourceId


class GetResolverQueryLogConfigResponse(TypedDict, total=False):
    ResolverQueryLogConfig: Optional[ResolverQueryLogConfig]


class GetResolverRuleAssociationRequest(ServiceRequest):
    ResolverRuleAssociationId: ResourceId


class GetResolverRuleAssociationResponse(TypedDict, total=False):
    ResolverRuleAssociation: Optional[ResolverRuleAssociation]


class GetResolverRulePolicyRequest(ServiceRequest):
    Arn: Arn


class GetResolverRulePolicyResponse(TypedDict, total=False):
    ResolverRulePolicy: Optional[ResolverRulePolicy]


class GetResolverRuleRequest(ServiceRequest):
    ResolverRuleId: ResourceId


class GetResolverRuleResponse(TypedDict, total=False):
    ResolverRule: Optional[ResolverRule]


class ImportFirewallDomainsRequest(ServiceRequest):
    FirewallDomainListId: ResourceId
    Operation: FirewallDomainImportOperation
    DomainFileUrl: DomainListFileUrl


class ImportFirewallDomainsResponse(TypedDict, total=False):
    Id: Optional[ResourceId]
    Name: Optional[Name]
    Status: Optional[FirewallDomainListStatus]
    StatusMessage: Optional[StatusMessage]


class IpAddressResponse(TypedDict, total=False):
    IpId: Optional[ResourceId]
    SubnetId: Optional[SubnetId]
    Ip: Optional[Ip]
    Status: Optional[IpAddressStatus]
    StatusMessage: Optional[StatusMessage]
    CreationTime: Optional[Rfc3339TimeString]
    ModificationTime: Optional[Rfc3339TimeString]


IpAddressesResponse = List[IpAddressResponse]


class ListFirewallConfigsRequest(ServiceRequest):
    MaxResults: Optional[ListFirewallConfigsMaxResult]
    NextToken: Optional[NextToken]


class ListFirewallConfigsResponse(TypedDict, total=False):
    NextToken: Optional[NextToken]
    FirewallConfigs: Optional[FirewallConfigList]


class ListFirewallDomainListsRequest(ServiceRequest):
    MaxResults: Optional[MaxResults]
    NextToken: Optional[NextToken]


class ListFirewallDomainListsResponse(TypedDict, total=False):
    NextToken: Optional[NextToken]
    FirewallDomainLists: Optional[FirewallDomainListMetadataList]


class ListFirewallDomainsRequest(ServiceRequest):
    FirewallDomainListId: ResourceId
    MaxResults: Optional[ListDomainMaxResults]
    NextToken: Optional[NextToken]


class ListFirewallDomainsResponse(TypedDict, total=False):
    NextToken: Optional[NextToken]
    Domains: Optional[FirewallDomains]


class ListFirewallRuleGroupAssociationsRequest(ServiceRequest):
    FirewallRuleGroupId: Optional[ResourceId]
    VpcId: Optional[ResourceId]
    Priority: Optional[Priority]
    Status: Optional[FirewallRuleGroupAssociationStatus]
    MaxResults: Optional[MaxResults]
    NextToken: Optional[NextToken]


class ListFirewallRuleGroupAssociationsResponse(TypedDict, total=False):
    NextToken: Optional[NextToken]
    FirewallRuleGroupAssociations: Optional[FirewallRuleGroupAssociations]


class ListFirewallRuleGroupsRequest(ServiceRequest):
    MaxResults: Optional[MaxResults]
    NextToken: Optional[NextToken]


class ListFirewallRuleGroupsResponse(TypedDict, total=False):
    NextToken: Optional[NextToken]
    FirewallRuleGroups: Optional[FirewallRuleGroupMetadataList]


class ListFirewallRulesRequest(ServiceRequest):
    FirewallRuleGroupId: ResourceId
    Priority: Optional[Priority]
    Action: Optional[Action]
    MaxResults: Optional[MaxResults]
    NextToken: Optional[NextToken]


class ListFirewallRulesResponse(TypedDict, total=False):
    NextToken: Optional[NextToken]
    FirewallRules: Optional[FirewallRules]


class ListResolverConfigsRequest(ServiceRequest):
    MaxResults: Optional[ListResolverConfigsMaxResult]
    NextToken: Optional[NextToken]


ResolverConfigList = List[ResolverConfig]


class ListResolverConfigsResponse(TypedDict, total=False):
    NextToken: Optional[NextToken]
    ResolverConfigs: Optional[ResolverConfigList]


class ListResolverDnssecConfigsRequest(ServiceRequest):
    MaxResults: Optional[MaxResults]
    NextToken: Optional[NextToken]
    Filters: Optional[Filters]


ResolverDnssecConfigList = List[ResolverDnssecConfig]


class ListResolverDnssecConfigsResponse(TypedDict, total=False):
    NextToken: Optional[NextToken]
    ResolverDnssecConfigs: Optional[ResolverDnssecConfigList]


class ListResolverEndpointIpAddressesRequest(ServiceRequest):
    ResolverEndpointId: ResourceId
    MaxResults: Optional[MaxResults]
    NextToken: Optional[NextToken]


class ListResolverEndpointIpAddressesResponse(TypedDict, total=False):
    NextToken: Optional[NextToken]
    MaxResults: Optional[MaxResults]
    IpAddresses: Optional[IpAddressesResponse]


class ListResolverEndpointsRequest(ServiceRequest):
    MaxResults: Optional[MaxResults]
    NextToken: Optional[NextToken]
    Filters: Optional[Filters]


ResolverEndpoints = List[ResolverEndpoint]


class ListResolverEndpointsResponse(TypedDict, total=False):
    NextToken: Optional[NextToken]
    MaxResults: Optional[MaxResults]
    ResolverEndpoints: Optional[ResolverEndpoints]


class ListResolverQueryLogConfigAssociationsRequest(ServiceRequest):
    MaxResults: Optional[MaxResults]
    NextToken: Optional[NextToken]
    Filters: Optional[Filters]
    SortBy: Optional[SortByKey]
    SortOrder: Optional[SortOrder]


ResolverQueryLogConfigAssociationList = List[ResolverQueryLogConfigAssociation]


class ListResolverQueryLogConfigAssociationsResponse(TypedDict, total=False):
    NextToken: Optional[NextToken]
    TotalCount: Optional[Count]
    TotalFilteredCount: Optional[Count]
    ResolverQueryLogConfigAssociations: Optional[ResolverQueryLogConfigAssociationList]


class ListResolverQueryLogConfigsRequest(ServiceRequest):
    MaxResults: Optional[MaxResults]
    NextToken: Optional[NextToken]
    Filters: Optional[Filters]
    SortBy: Optional[SortByKey]
    SortOrder: Optional[SortOrder]


ResolverQueryLogConfigList = List[ResolverQueryLogConfig]


class ListResolverQueryLogConfigsResponse(TypedDict, total=False):
    NextToken: Optional[NextToken]
    TotalCount: Optional[Count]
    TotalFilteredCount: Optional[Count]
    ResolverQueryLogConfigs: Optional[ResolverQueryLogConfigList]


class ListResolverRuleAssociationsRequest(ServiceRequest):
    MaxResults: Optional[MaxResults]
    NextToken: Optional[NextToken]
    Filters: Optional[Filters]


ResolverRuleAssociations = List[ResolverRuleAssociation]


class ListResolverRuleAssociationsResponse(TypedDict, total=False):
    NextToken: Optional[NextToken]
    MaxResults: Optional[MaxResults]
    ResolverRuleAssociations: Optional[ResolverRuleAssociations]


class ListResolverRulesRequest(ServiceRequest):
    MaxResults: Optional[MaxResults]
    NextToken: Optional[NextToken]
    Filters: Optional[Filters]


ResolverRules = List[ResolverRule]


class ListResolverRulesResponse(TypedDict, total=False):
    NextToken: Optional[NextToken]
    MaxResults: Optional[MaxResults]
    ResolverRules: Optional[ResolverRules]


class ListTagsForResourceRequest(ServiceRequest):
    ResourceArn: Arn
    MaxResults: Optional[MaxResults]
    NextToken: Optional[NextToken]


class ListTagsForResourceResponse(TypedDict, total=False):
    Tags: Optional[TagList]
    NextToken: Optional[NextToken]


class PutFirewallRuleGroupPolicyRequest(ServiceRequest):
    Arn: Arn
    FirewallRuleGroupPolicy: FirewallRuleGroupPolicy


class PutFirewallRuleGroupPolicyResponse(TypedDict, total=False):
    ReturnValue: Optional[Boolean]


class PutResolverQueryLogConfigPolicyRequest(ServiceRequest):
    Arn: Arn
    ResolverQueryLogConfigPolicy: ResolverQueryLogConfigPolicy


class PutResolverQueryLogConfigPolicyResponse(TypedDict, total=False):
    ReturnValue: Optional[Boolean]


class PutResolverRulePolicyRequest(ServiceRequest):
    Arn: Arn
    ResolverRulePolicy: ResolverRulePolicy


class PutResolverRulePolicyResponse(TypedDict, total=False):
    ReturnValue: Optional[Boolean]


class ResolverRuleConfig(TypedDict, total=False):
    Name: Optional[Name]
    TargetIps: Optional[TargetList]
    ResolverEndpointId: Optional[ResourceId]


TagKeyList = List[TagKey]


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
    FirewallConfig: Optional[FirewallConfig]


class UpdateFirewallDomainsRequest(ServiceRequest):
    FirewallDomainListId: ResourceId
    Operation: FirewallDomainUpdateOperation
    Domains: FirewallDomains


class UpdateFirewallDomainsResponse(TypedDict, total=False):
    Id: Optional[ResourceId]
    Name: Optional[Name]
    Status: Optional[FirewallDomainListStatus]
    StatusMessage: Optional[StatusMessage]


class UpdateFirewallRuleGroupAssociationRequest(ServiceRequest):
    FirewallRuleGroupAssociationId: ResourceId
    Priority: Optional[Priority]
    MutationProtection: Optional[MutationProtectionStatus]
    Name: Optional[Name]


class UpdateFirewallRuleGroupAssociationResponse(TypedDict, total=False):
    FirewallRuleGroupAssociation: Optional[FirewallRuleGroupAssociation]


class UpdateFirewallRuleRequest(ServiceRequest):
    FirewallRuleGroupId: ResourceId
    FirewallDomainListId: ResourceId
    Priority: Optional[Priority]
    Action: Optional[Action]
    BlockResponse: Optional[BlockResponse]
    BlockOverrideDomain: Optional[BlockOverrideDomain]
    BlockOverrideDnsType: Optional[BlockOverrideDnsType]
    BlockOverrideTtl: Optional[BlockOverrideTtl]
    Name: Optional[Name]


class UpdateFirewallRuleResponse(TypedDict, total=False):
    FirewallRule: Optional[FirewallRule]


class UpdateResolverConfigRequest(ServiceRequest):
    ResourceId: ResourceId
    AutodefinedReverseFlag: AutodefinedReverseFlag


class UpdateResolverConfigResponse(TypedDict, total=False):
    ResolverConfig: Optional[ResolverConfig]


class UpdateResolverDnssecConfigRequest(ServiceRequest):
    ResourceId: ResourceId
    Validation: Validation


class UpdateResolverDnssecConfigResponse(TypedDict, total=False):
    ResolverDNSSECConfig: Optional[ResolverDnssecConfig]


class UpdateResolverEndpointRequest(ServiceRequest):
    ResolverEndpointId: ResourceId
    Name: Optional[Name]


class UpdateResolverEndpointResponse(TypedDict, total=False):
    ResolverEndpoint: Optional[ResolverEndpoint]


class UpdateResolverRuleRequest(ServiceRequest):
    ResolverRuleId: ResourceId
    Config: ResolverRuleConfig


class UpdateResolverRuleResponse(TypedDict, total=False):
    ResolverRule: Optional[ResolverRule]


class Route53ResolverApi:

    service = "route53resolver"
    version = "2018-04-01"

    @handler("AssociateFirewallRuleGroup")
    def associate_firewall_rule_group(
        self,
        context: RequestContext,
        creator_request_id: CreatorRequestId,
        firewall_rule_group_id: ResourceId,
        vpc_id: ResourceId,
        priority: Priority,
        name: Name,
        mutation_protection: MutationProtectionStatus = None,
        tags: TagList = None,
    ) -> AssociateFirewallRuleGroupResponse:
        raise NotImplementedError

    @handler("AssociateResolverEndpointIpAddress")
    def associate_resolver_endpoint_ip_address(
        self, context: RequestContext, resolver_endpoint_id: ResourceId, ip_address: IpAddressUpdate
    ) -> AssociateResolverEndpointIpAddressResponse:
        raise NotImplementedError

    @handler("AssociateResolverQueryLogConfig")
    def associate_resolver_query_log_config(
        self,
        context: RequestContext,
        resolver_query_log_config_id: ResourceId,
        resource_id: ResourceId,
    ) -> AssociateResolverQueryLogConfigResponse:
        raise NotImplementedError

    @handler("AssociateResolverRule")
    def associate_resolver_rule(
        self,
        context: RequestContext,
        resolver_rule_id: ResourceId,
        vpc_id: ResourceId,
        name: Name = None,
    ) -> AssociateResolverRuleResponse:
        raise NotImplementedError

    @handler("CreateFirewallDomainList")
    def create_firewall_domain_list(
        self,
        context: RequestContext,
        creator_request_id: CreatorRequestId,
        name: Name,
        tags: TagList = None,
    ) -> CreateFirewallDomainListResponse:
        raise NotImplementedError

    @handler("CreateFirewallRule")
    def create_firewall_rule(
        self,
        context: RequestContext,
        creator_request_id: CreatorRequestId,
        firewall_rule_group_id: ResourceId,
        firewall_domain_list_id: ResourceId,
        priority: Priority,
        action: Action,
        name: Name,
        block_response: BlockResponse = None,
        block_override_domain: BlockOverrideDomain = None,
        block_override_dns_type: BlockOverrideDnsType = None,
        block_override_ttl: BlockOverrideTtl = None,
    ) -> CreateFirewallRuleResponse:
        raise NotImplementedError

    @handler("CreateFirewallRuleGroup")
    def create_firewall_rule_group(
        self,
        context: RequestContext,
        creator_request_id: CreatorRequestId,
        name: Name,
        tags: TagList = None,
    ) -> CreateFirewallRuleGroupResponse:
        raise NotImplementedError

    @handler("CreateResolverEndpoint")
    def create_resolver_endpoint(
        self,
        context: RequestContext,
        creator_request_id: CreatorRequestId,
        security_group_ids: SecurityGroupIds,
        direction: ResolverEndpointDirection,
        ip_addresses: IpAddressesRequest,
        name: Name = None,
        tags: TagList = None,
    ) -> CreateResolverEndpointResponse:
        raise NotImplementedError

    @handler("CreateResolverQueryLogConfig")
    def create_resolver_query_log_config(
        self,
        context: RequestContext,
        name: ResolverQueryLogConfigName,
        destination_arn: DestinationArn,
        creator_request_id: CreatorRequestId,
        tags: TagList = None,
    ) -> CreateResolverQueryLogConfigResponse:
        raise NotImplementedError

    @handler("CreateResolverRule")
    def create_resolver_rule(
        self,
        context: RequestContext,
        creator_request_id: CreatorRequestId,
        rule_type: RuleTypeOption,
        domain_name: DomainName,
        name: Name = None,
        target_ips: TargetList = None,
        resolver_endpoint_id: ResourceId = None,
        tags: TagList = None,
    ) -> CreateResolverRuleResponse:
        raise NotImplementedError

    @handler("DeleteFirewallDomainList")
    def delete_firewall_domain_list(
        self, context: RequestContext, firewall_domain_list_id: ResourceId
    ) -> DeleteFirewallDomainListResponse:
        raise NotImplementedError

    @handler("DeleteFirewallRule")
    def delete_firewall_rule(
        self,
        context: RequestContext,
        firewall_rule_group_id: ResourceId,
        firewall_domain_list_id: ResourceId,
    ) -> DeleteFirewallRuleResponse:
        raise NotImplementedError

    @handler("DeleteFirewallRuleGroup")
    def delete_firewall_rule_group(
        self, context: RequestContext, firewall_rule_group_id: ResourceId
    ) -> DeleteFirewallRuleGroupResponse:
        raise NotImplementedError

    @handler("DeleteResolverEndpoint")
    def delete_resolver_endpoint(
        self, context: RequestContext, resolver_endpoint_id: ResourceId
    ) -> DeleteResolverEndpointResponse:
        raise NotImplementedError

    @handler("DeleteResolverQueryLogConfig")
    def delete_resolver_query_log_config(
        self, context: RequestContext, resolver_query_log_config_id: ResourceId
    ) -> DeleteResolverQueryLogConfigResponse:
        raise NotImplementedError

    @handler("DeleteResolverRule")
    def delete_resolver_rule(
        self, context: RequestContext, resolver_rule_id: ResourceId
    ) -> DeleteResolverRuleResponse:
        raise NotImplementedError

    @handler("DisassociateFirewallRuleGroup")
    def disassociate_firewall_rule_group(
        self, context: RequestContext, firewall_rule_group_association_id: ResourceId
    ) -> DisassociateFirewallRuleGroupResponse:
        raise NotImplementedError

    @handler("DisassociateResolverEndpointIpAddress")
    def disassociate_resolver_endpoint_ip_address(
        self, context: RequestContext, resolver_endpoint_id: ResourceId, ip_address: IpAddressUpdate
    ) -> DisassociateResolverEndpointIpAddressResponse:
        raise NotImplementedError

    @handler("DisassociateResolverQueryLogConfig")
    def disassociate_resolver_query_log_config(
        self,
        context: RequestContext,
        resolver_query_log_config_id: ResourceId,
        resource_id: ResourceId,
    ) -> DisassociateResolverQueryLogConfigResponse:
        raise NotImplementedError

    @handler("DisassociateResolverRule")
    def disassociate_resolver_rule(
        self, context: RequestContext, vpc_id: ResourceId, resolver_rule_id: ResourceId
    ) -> DisassociateResolverRuleResponse:
        raise NotImplementedError

    @handler("GetFirewallConfig")
    def get_firewall_config(
        self, context: RequestContext, resource_id: ResourceId
    ) -> GetFirewallConfigResponse:
        raise NotImplementedError

    @handler("GetFirewallDomainList")
    def get_firewall_domain_list(
        self, context: RequestContext, firewall_domain_list_id: ResourceId
    ) -> GetFirewallDomainListResponse:
        raise NotImplementedError

    @handler("GetFirewallRuleGroup")
    def get_firewall_rule_group(
        self, context: RequestContext, firewall_rule_group_id: ResourceId
    ) -> GetFirewallRuleGroupResponse:
        raise NotImplementedError

    @handler("GetFirewallRuleGroupAssociation")
    def get_firewall_rule_group_association(
        self, context: RequestContext, firewall_rule_group_association_id: ResourceId
    ) -> GetFirewallRuleGroupAssociationResponse:
        raise NotImplementedError

    @handler("GetFirewallRuleGroupPolicy")
    def get_firewall_rule_group_policy(
        self, context: RequestContext, arn: Arn
    ) -> GetFirewallRuleGroupPolicyResponse:
        raise NotImplementedError

    @handler("GetResolverConfig")
    def get_resolver_config(
        self, context: RequestContext, resource_id: ResourceId
    ) -> GetResolverConfigResponse:
        raise NotImplementedError

    @handler("GetResolverDnssecConfig")
    def get_resolver_dnssec_config(
        self, context: RequestContext, resource_id: ResourceId
    ) -> GetResolverDnssecConfigResponse:
        raise NotImplementedError

    @handler("GetResolverEndpoint")
    def get_resolver_endpoint(
        self, context: RequestContext, resolver_endpoint_id: ResourceId
    ) -> GetResolverEndpointResponse:
        raise NotImplementedError

    @handler("GetResolverQueryLogConfig")
    def get_resolver_query_log_config(
        self, context: RequestContext, resolver_query_log_config_id: ResourceId
    ) -> GetResolverQueryLogConfigResponse:
        raise NotImplementedError

    @handler("GetResolverQueryLogConfigAssociation")
    def get_resolver_query_log_config_association(
        self, context: RequestContext, resolver_query_log_config_association_id: ResourceId
    ) -> GetResolverQueryLogConfigAssociationResponse:
        raise NotImplementedError

    @handler("GetResolverQueryLogConfigPolicy")
    def get_resolver_query_log_config_policy(
        self, context: RequestContext, arn: Arn
    ) -> GetResolverQueryLogConfigPolicyResponse:
        raise NotImplementedError

    @handler("GetResolverRule")
    def get_resolver_rule(
        self, context: RequestContext, resolver_rule_id: ResourceId
    ) -> GetResolverRuleResponse:
        raise NotImplementedError

    @handler("GetResolverRuleAssociation")
    def get_resolver_rule_association(
        self, context: RequestContext, resolver_rule_association_id: ResourceId
    ) -> GetResolverRuleAssociationResponse:
        raise NotImplementedError

    @handler("GetResolverRulePolicy")
    def get_resolver_rule_policy(
        self, context: RequestContext, arn: Arn
    ) -> GetResolverRulePolicyResponse:
        raise NotImplementedError

    @handler("ImportFirewallDomains")
    def import_firewall_domains(
        self,
        context: RequestContext,
        firewall_domain_list_id: ResourceId,
        operation: FirewallDomainImportOperation,
        domain_file_url: DomainListFileUrl,
    ) -> ImportFirewallDomainsResponse:
        raise NotImplementedError

    @handler("ListFirewallConfigs")
    def list_firewall_configs(
        self,
        context: RequestContext,
        max_results: ListFirewallConfigsMaxResult = None,
        next_token: NextToken = None,
    ) -> ListFirewallConfigsResponse:
        raise NotImplementedError

    @handler("ListFirewallDomainLists")
    def list_firewall_domain_lists(
        self, context: RequestContext, max_results: MaxResults = None, next_token: NextToken = None
    ) -> ListFirewallDomainListsResponse:
        raise NotImplementedError

    @handler("ListFirewallDomains")
    def list_firewall_domains(
        self,
        context: RequestContext,
        firewall_domain_list_id: ResourceId,
        max_results: ListDomainMaxResults = None,
        next_token: NextToken = None,
    ) -> ListFirewallDomainsResponse:
        raise NotImplementedError

    @handler("ListFirewallRuleGroupAssociations")
    def list_firewall_rule_group_associations(
        self,
        context: RequestContext,
        firewall_rule_group_id: ResourceId = None,
        vpc_id: ResourceId = None,
        priority: Priority = None,
        status: FirewallRuleGroupAssociationStatus = None,
        max_results: MaxResults = None,
        next_token: NextToken = None,
    ) -> ListFirewallRuleGroupAssociationsResponse:
        raise NotImplementedError

    @handler("ListFirewallRuleGroups")
    def list_firewall_rule_groups(
        self, context: RequestContext, max_results: MaxResults = None, next_token: NextToken = None
    ) -> ListFirewallRuleGroupsResponse:
        raise NotImplementedError

    @handler("ListFirewallRules")
    def list_firewall_rules(
        self,
        context: RequestContext,
        firewall_rule_group_id: ResourceId,
        priority: Priority = None,
        action: Action = None,
        max_results: MaxResults = None,
        next_token: NextToken = None,
    ) -> ListFirewallRulesResponse:
        raise NotImplementedError

    @handler("ListResolverConfigs")
    def list_resolver_configs(
        self,
        context: RequestContext,
        max_results: ListResolverConfigsMaxResult = None,
        next_token: NextToken = None,
    ) -> ListResolverConfigsResponse:
        raise NotImplementedError

    @handler("ListResolverDnssecConfigs")
    def list_resolver_dnssec_configs(
        self,
        context: RequestContext,
        max_results: MaxResults = None,
        next_token: NextToken = None,
        filters: Filters = None,
    ) -> ListResolverDnssecConfigsResponse:
        raise NotImplementedError

    @handler("ListResolverEndpointIpAddresses")
    def list_resolver_endpoint_ip_addresses(
        self,
        context: RequestContext,
        resolver_endpoint_id: ResourceId,
        max_results: MaxResults = None,
        next_token: NextToken = None,
    ) -> ListResolverEndpointIpAddressesResponse:
        raise NotImplementedError

    @handler("ListResolverEndpoints")
    def list_resolver_endpoints(
        self,
        context: RequestContext,
        max_results: MaxResults = None,
        next_token: NextToken = None,
        filters: Filters = None,
    ) -> ListResolverEndpointsResponse:
        raise NotImplementedError

    @handler("ListResolverQueryLogConfigAssociations")
    def list_resolver_query_log_config_associations(
        self,
        context: RequestContext,
        max_results: MaxResults = None,
        next_token: NextToken = None,
        filters: Filters = None,
        sort_by: SortByKey = None,
        sort_order: SortOrder = None,
    ) -> ListResolverQueryLogConfigAssociationsResponse:
        raise NotImplementedError

    @handler("ListResolverQueryLogConfigs")
    def list_resolver_query_log_configs(
        self,
        context: RequestContext,
        max_results: MaxResults = None,
        next_token: NextToken = None,
        filters: Filters = None,
        sort_by: SortByKey = None,
        sort_order: SortOrder = None,
    ) -> ListResolverQueryLogConfigsResponse:
        raise NotImplementedError

    @handler("ListResolverRuleAssociations")
    def list_resolver_rule_associations(
        self,
        context: RequestContext,
        max_results: MaxResults = None,
        next_token: NextToken = None,
        filters: Filters = None,
    ) -> ListResolverRuleAssociationsResponse:
        raise NotImplementedError

    @handler("ListResolverRules")
    def list_resolver_rules(
        self,
        context: RequestContext,
        max_results: MaxResults = None,
        next_token: NextToken = None,
        filters: Filters = None,
    ) -> ListResolverRulesResponse:
        raise NotImplementedError

    @handler("ListTagsForResource")
    def list_tags_for_resource(
        self,
        context: RequestContext,
        resource_arn: Arn,
        max_results: MaxResults = None,
        next_token: NextToken = None,
    ) -> ListTagsForResourceResponse:
        raise NotImplementedError

    @handler("PutFirewallRuleGroupPolicy")
    def put_firewall_rule_group_policy(
        self, context: RequestContext, arn: Arn, firewall_rule_group_policy: FirewallRuleGroupPolicy
    ) -> PutFirewallRuleGroupPolicyResponse:
        raise NotImplementedError

    @handler("PutResolverQueryLogConfigPolicy")
    def put_resolver_query_log_config_policy(
        self,
        context: RequestContext,
        arn: Arn,
        resolver_query_log_config_policy: ResolverQueryLogConfigPolicy,
    ) -> PutResolverQueryLogConfigPolicyResponse:
        raise NotImplementedError

    @handler("PutResolverRulePolicy")
    def put_resolver_rule_policy(
        self, context: RequestContext, arn: Arn, resolver_rule_policy: ResolverRulePolicy
    ) -> PutResolverRulePolicyResponse:
        raise NotImplementedError

    @handler("TagResource")
    def tag_resource(
        self, context: RequestContext, resource_arn: Arn, tags: TagList
    ) -> TagResourceResponse:
        raise NotImplementedError

    @handler("UntagResource")
    def untag_resource(
        self, context: RequestContext, resource_arn: Arn, tag_keys: TagKeyList
    ) -> UntagResourceResponse:
        raise NotImplementedError

    @handler("UpdateFirewallConfig")
    def update_firewall_config(
        self,
        context: RequestContext,
        resource_id: ResourceId,
        firewall_fail_open: FirewallFailOpenStatus,
    ) -> UpdateFirewallConfigResponse:
        raise NotImplementedError

    @handler("UpdateFirewallDomains")
    def update_firewall_domains(
        self,
        context: RequestContext,
        firewall_domain_list_id: ResourceId,
        operation: FirewallDomainUpdateOperation,
        domains: FirewallDomains,
    ) -> UpdateFirewallDomainsResponse:
        raise NotImplementedError

    @handler("UpdateFirewallRule")
    def update_firewall_rule(
        self,
        context: RequestContext,
        firewall_rule_group_id: ResourceId,
        firewall_domain_list_id: ResourceId,
        priority: Priority = None,
        action: Action = None,
        block_response: BlockResponse = None,
        block_override_domain: BlockOverrideDomain = None,
        block_override_dns_type: BlockOverrideDnsType = None,
        block_override_ttl: BlockOverrideTtl = None,
        name: Name = None,
    ) -> UpdateFirewallRuleResponse:
        raise NotImplementedError

    @handler("UpdateFirewallRuleGroupAssociation")
    def update_firewall_rule_group_association(
        self,
        context: RequestContext,
        firewall_rule_group_association_id: ResourceId,
        priority: Priority = None,
        mutation_protection: MutationProtectionStatus = None,
        name: Name = None,
    ) -> UpdateFirewallRuleGroupAssociationResponse:
        raise NotImplementedError

    @handler("UpdateResolverConfig")
    def update_resolver_config(
        self,
        context: RequestContext,
        resource_id: ResourceId,
        autodefined_reverse_flag: AutodefinedReverseFlag,
    ) -> UpdateResolverConfigResponse:
        raise NotImplementedError

    @handler("UpdateResolverDnssecConfig")
    def update_resolver_dnssec_config(
        self, context: RequestContext, resource_id: ResourceId, validation: Validation
    ) -> UpdateResolverDnssecConfigResponse:
        raise NotImplementedError

    @handler("UpdateResolverEndpoint")
    def update_resolver_endpoint(
        self, context: RequestContext, resolver_endpoint_id: ResourceId, name: Name = None
    ) -> UpdateResolverEndpointResponse:
        raise NotImplementedError

    @handler("UpdateResolverRule")
    def update_resolver_rule(
        self, context: RequestContext, resolver_rule_id: ResourceId, config: ResolverRuleConfig
    ) -> UpdateResolverRuleResponse:
        raise NotImplementedError
