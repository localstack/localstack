from datetime import datetime
from typing import List, Optional, TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

Boolean = bool
Integer = int
MaxResults = int
PermissionName = str
Policy = str
String = str
TagKey = str
TagValue = str


class PermissionFeatureSet(str):
    CREATED_FROM_POLICY = "CREATED_FROM_POLICY"
    PROMOTING_TO_STANDARD = "PROMOTING_TO_STANDARD"
    STANDARD = "STANDARD"


class PermissionStatus(str):
    ATTACHABLE = "ATTACHABLE"
    UNATTACHABLE = "UNATTACHABLE"
    DELETING = "DELETING"
    DELETED = "DELETED"


class PermissionType(str):
    CUSTOMER_MANAGED = "CUSTOMER_MANAGED"
    AWS_MANAGED = "AWS_MANAGED"


class PermissionTypeFilter(str):
    ALL = "ALL"
    AWS_MANAGED = "AWS_MANAGED"
    CUSTOMER_MANAGED = "CUSTOMER_MANAGED"


class ReplacePermissionAssociationsWorkStatus(str):
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class ResourceOwner(str):
    SELF = "SELF"
    OTHER_ACCOUNTS = "OTHER-ACCOUNTS"


class ResourceRegionScope(str):
    REGIONAL = "REGIONAL"
    GLOBAL = "GLOBAL"


class ResourceRegionScopeFilter(str):
    ALL = "ALL"
    REGIONAL = "REGIONAL"
    GLOBAL = "GLOBAL"


class ResourceShareAssociationStatus(str):
    ASSOCIATING = "ASSOCIATING"
    ASSOCIATED = "ASSOCIATED"
    FAILED = "FAILED"
    DISASSOCIATING = "DISASSOCIATING"
    DISASSOCIATED = "DISASSOCIATED"


class ResourceShareAssociationType(str):
    PRINCIPAL = "PRINCIPAL"
    RESOURCE = "RESOURCE"


class ResourceShareFeatureSet(str):
    CREATED_FROM_POLICY = "CREATED_FROM_POLICY"
    PROMOTING_TO_STANDARD = "PROMOTING_TO_STANDARD"
    STANDARD = "STANDARD"


class ResourceShareInvitationStatus(str):
    PENDING = "PENDING"
    ACCEPTED = "ACCEPTED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"


class ResourceShareStatus(str):
    PENDING = "PENDING"
    ACTIVE = "ACTIVE"
    FAILED = "FAILED"
    DELETING = "DELETING"
    DELETED = "DELETED"


class ResourceStatus(str):
    AVAILABLE = "AVAILABLE"
    ZONAL_RESOURCE_INACCESSIBLE = "ZONAL_RESOURCE_INACCESSIBLE"
    LIMIT_EXCEEDED = "LIMIT_EXCEEDED"
    UNAVAILABLE = "UNAVAILABLE"
    PENDING = "PENDING"


class IdempotentParameterMismatchException(ServiceException):
    code: str = "IdempotentParameterMismatchException"
    sender_fault: bool = False
    status_code: int = 400


class InvalidClientTokenException(ServiceException):
    code: str = "InvalidClientTokenException"
    sender_fault: bool = False
    status_code: int = 400


class InvalidMaxResultsException(ServiceException):
    code: str = "InvalidMaxResultsException"
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


class InvalidPolicyException(ServiceException):
    code: str = "InvalidPolicyException"
    sender_fault: bool = False
    status_code: int = 400


class InvalidResourceTypeException(ServiceException):
    code: str = "InvalidResourceTypeException"
    sender_fault: bool = False
    status_code: int = 400


class InvalidStateTransitionException(ServiceException):
    code: str = "InvalidStateTransitionException"
    sender_fault: bool = False
    status_code: int = 400


class MalformedArnException(ServiceException):
    code: str = "MalformedArnException"
    sender_fault: bool = False
    status_code: int = 400


class MalformedPolicyTemplateException(ServiceException):
    code: str = "MalformedPolicyTemplateException"
    sender_fault: bool = False
    status_code: int = 400


class MissingRequiredParameterException(ServiceException):
    code: str = "MissingRequiredParameterException"
    sender_fault: bool = False
    status_code: int = 400


class OperationNotPermittedException(ServiceException):
    code: str = "OperationNotPermittedException"
    sender_fault: bool = False
    status_code: int = 400


class PermissionAlreadyExistsException(ServiceException):
    code: str = "PermissionAlreadyExistsException"
    sender_fault: bool = False
    status_code: int = 409


class PermissionLimitExceededException(ServiceException):
    code: str = "PermissionLimitExceededException"
    sender_fault: bool = False
    status_code: int = 400


class PermissionVersionsLimitExceededException(ServiceException):
    code: str = "PermissionVersionsLimitExceededException"
    sender_fault: bool = False
    status_code: int = 400


class ResourceArnNotFoundException(ServiceException):
    code: str = "ResourceArnNotFoundException"
    sender_fault: bool = False
    status_code: int = 400


class ResourceShareInvitationAlreadyAcceptedException(ServiceException):
    code: str = "ResourceShareInvitationAlreadyAcceptedException"
    sender_fault: bool = False
    status_code: int = 400


class ResourceShareInvitationAlreadyRejectedException(ServiceException):
    code: str = "ResourceShareInvitationAlreadyRejectedException"
    sender_fault: bool = False
    status_code: int = 400


class ResourceShareInvitationArnNotFoundException(ServiceException):
    code: str = "ResourceShareInvitationArnNotFoundException"
    sender_fault: bool = False
    status_code: int = 400


class ResourceShareInvitationExpiredException(ServiceException):
    code: str = "ResourceShareInvitationExpiredException"
    sender_fault: bool = False
    status_code: int = 400


class ResourceShareLimitExceededException(ServiceException):
    code: str = "ResourceShareLimitExceededException"
    sender_fault: bool = False
    status_code: int = 400


class ServerInternalException(ServiceException):
    code: str = "ServerInternalException"
    sender_fault: bool = False
    status_code: int = 500


class ServiceUnavailableException(ServiceException):
    code: str = "ServiceUnavailableException"
    sender_fault: bool = False
    status_code: int = 503


class TagLimitExceededException(ServiceException):
    code: str = "TagLimitExceededException"
    sender_fault: bool = False
    status_code: int = 400


class TagPolicyViolationException(ServiceException):
    code: str = "TagPolicyViolationException"
    sender_fault: bool = False
    status_code: int = 400


class ThrottlingException(ServiceException):
    code: str = "ThrottlingException"
    sender_fault: bool = False
    status_code: int = 429


class UnknownResourceException(ServiceException):
    code: str = "UnknownResourceException"
    sender_fault: bool = False
    status_code: int = 400


class UnmatchedPolicyPermissionException(ServiceException):
    code: str = "UnmatchedPolicyPermissionException"
    sender_fault: bool = False
    status_code: int = 400


class AcceptResourceShareInvitationRequest(ServiceRequest):
    resourceShareInvitationArn: String
    clientToken: Optional[String]


DateTime = datetime


class ResourceShareAssociation(TypedDict, total=False):
    resourceShareArn: Optional[String]
    resourceShareName: Optional[String]
    associatedEntity: Optional[String]
    associationType: Optional[ResourceShareAssociationType]
    status: Optional[ResourceShareAssociationStatus]
    statusMessage: Optional[String]
    creationTime: Optional[DateTime]
    lastUpdatedTime: Optional[DateTime]
    external: Optional[Boolean]


ResourceShareAssociationList = List[ResourceShareAssociation]


class ResourceShareInvitation(TypedDict, total=False):
    resourceShareInvitationArn: Optional[String]
    resourceShareName: Optional[String]
    resourceShareArn: Optional[String]
    senderAccountId: Optional[String]
    receiverAccountId: Optional[String]
    invitationTimestamp: Optional[DateTime]
    status: Optional[ResourceShareInvitationStatus]
    resourceShareAssociations: Optional[ResourceShareAssociationList]
    receiverArn: Optional[String]


class AcceptResourceShareInvitationResponse(TypedDict, total=False):
    resourceShareInvitation: Optional[ResourceShareInvitation]
    clientToken: Optional[String]


class AssociateResourceSharePermissionRequest(ServiceRequest):
    resourceShareArn: String
    permissionArn: String
    replace: Optional[Boolean]
    clientToken: Optional[String]
    permissionVersion: Optional[Integer]


class AssociateResourceSharePermissionResponse(TypedDict, total=False):
    returnValue: Optional[Boolean]
    clientToken: Optional[String]


SourceArnOrAccountList = List[String]
PrincipalArnOrIdList = List[String]
ResourceArnList = List[String]


class AssociateResourceShareRequest(ServiceRequest):
    resourceShareArn: String
    resourceArns: Optional[ResourceArnList]
    principals: Optional[PrincipalArnOrIdList]
    clientToken: Optional[String]
    sources: Optional[SourceArnOrAccountList]


class AssociateResourceShareResponse(TypedDict, total=False):
    resourceShareAssociations: Optional[ResourceShareAssociationList]
    clientToken: Optional[String]


class AssociatedPermission(TypedDict, total=False):
    arn: Optional[String]
    permissionVersion: Optional[String]
    defaultVersion: Optional[Boolean]
    resourceType: Optional[String]
    status: Optional[String]
    featureSet: Optional[PermissionFeatureSet]
    lastUpdatedTime: Optional[DateTime]
    resourceShareArn: Optional[String]


AssociatedPermissionList = List[AssociatedPermission]


class Tag(TypedDict, total=False):
    key: Optional[TagKey]
    value: Optional[TagValue]


TagList = List[Tag]


class CreatePermissionRequest(ServiceRequest):
    name: PermissionName
    resourceType: String
    policyTemplate: Policy
    clientToken: Optional[String]
    tags: Optional[TagList]


class ResourceSharePermissionSummary(TypedDict, total=False):
    arn: Optional[String]
    version: Optional[String]
    defaultVersion: Optional[Boolean]
    name: Optional[String]
    resourceType: Optional[String]
    status: Optional[String]
    creationTime: Optional[DateTime]
    lastUpdatedTime: Optional[DateTime]
    isResourceTypeDefault: Optional[Boolean]
    permissionType: Optional[PermissionType]
    featureSet: Optional[PermissionFeatureSet]
    tags: Optional[TagList]


class CreatePermissionResponse(TypedDict, total=False):
    permission: Optional[ResourceSharePermissionSummary]
    clientToken: Optional[String]


class CreatePermissionVersionRequest(ServiceRequest):
    permissionArn: String
    policyTemplate: Policy
    clientToken: Optional[String]


class ResourceSharePermissionDetail(TypedDict, total=False):
    arn: Optional[String]
    version: Optional[String]
    defaultVersion: Optional[Boolean]
    name: Optional[String]
    resourceType: Optional[String]
    permission: Optional[String]
    creationTime: Optional[DateTime]
    lastUpdatedTime: Optional[DateTime]
    isResourceTypeDefault: Optional[Boolean]
    permissionType: Optional[PermissionType]
    featureSet: Optional[PermissionFeatureSet]
    status: Optional[PermissionStatus]
    tags: Optional[TagList]


class CreatePermissionVersionResponse(TypedDict, total=False):
    permission: Optional[ResourceSharePermissionDetail]
    clientToken: Optional[String]


PermissionArnList = List[String]


class CreateResourceShareRequest(ServiceRequest):
    name: String
    resourceArns: Optional[ResourceArnList]
    principals: Optional[PrincipalArnOrIdList]
    tags: Optional[TagList]
    allowExternalPrincipals: Optional[Boolean]
    clientToken: Optional[String]
    permissionArns: Optional[PermissionArnList]
    sources: Optional[SourceArnOrAccountList]


class ResourceShare(TypedDict, total=False):
    resourceShareArn: Optional[String]
    name: Optional[String]
    owningAccountId: Optional[String]
    allowExternalPrincipals: Optional[Boolean]
    status: Optional[ResourceShareStatus]
    statusMessage: Optional[String]
    tags: Optional[TagList]
    creationTime: Optional[DateTime]
    lastUpdatedTime: Optional[DateTime]
    featureSet: Optional[ResourceShareFeatureSet]


class CreateResourceShareResponse(TypedDict, total=False):
    resourceShare: Optional[ResourceShare]
    clientToken: Optional[String]


class DeletePermissionRequest(ServiceRequest):
    permissionArn: String
    clientToken: Optional[String]


class DeletePermissionResponse(TypedDict, total=False):
    returnValue: Optional[Boolean]
    clientToken: Optional[String]
    permissionStatus: Optional[PermissionStatus]


class DeletePermissionVersionRequest(ServiceRequest):
    permissionArn: String
    permissionVersion: Integer
    clientToken: Optional[String]


class DeletePermissionVersionResponse(TypedDict, total=False):
    returnValue: Optional[Boolean]
    clientToken: Optional[String]
    permissionStatus: Optional[PermissionStatus]


class DeleteResourceShareRequest(ServiceRequest):
    resourceShareArn: String
    clientToken: Optional[String]


class DeleteResourceShareResponse(TypedDict, total=False):
    returnValue: Optional[Boolean]
    clientToken: Optional[String]


class DisassociateResourceSharePermissionRequest(ServiceRequest):
    resourceShareArn: String
    permissionArn: String
    clientToken: Optional[String]


class DisassociateResourceSharePermissionResponse(TypedDict, total=False):
    returnValue: Optional[Boolean]
    clientToken: Optional[String]


class DisassociateResourceShareRequest(ServiceRequest):
    resourceShareArn: String
    resourceArns: Optional[ResourceArnList]
    principals: Optional[PrincipalArnOrIdList]
    clientToken: Optional[String]
    sources: Optional[SourceArnOrAccountList]


class DisassociateResourceShareResponse(TypedDict, total=False):
    resourceShareAssociations: Optional[ResourceShareAssociationList]
    clientToken: Optional[String]


class EnableSharingWithAwsOrganizationRequest(ServiceRequest):
    pass


class EnableSharingWithAwsOrganizationResponse(TypedDict, total=False):
    returnValue: Optional[Boolean]


class GetPermissionRequest(ServiceRequest):
    permissionArn: String
    permissionVersion: Optional[Integer]


class GetPermissionResponse(TypedDict, total=False):
    permission: Optional[ResourceSharePermissionDetail]


class GetResourcePoliciesRequest(ServiceRequest):
    resourceArns: ResourceArnList
    principal: Optional[String]
    nextToken: Optional[String]
    maxResults: Optional[MaxResults]


PolicyList = List[Policy]


class GetResourcePoliciesResponse(TypedDict, total=False):
    policies: Optional[PolicyList]
    nextToken: Optional[String]


ResourceShareArnList = List[String]


class GetResourceShareAssociationsRequest(ServiceRequest):
    associationType: ResourceShareAssociationType
    resourceShareArns: Optional[ResourceShareArnList]
    resourceArn: Optional[String]
    principal: Optional[String]
    associationStatus: Optional[ResourceShareAssociationStatus]
    nextToken: Optional[String]
    maxResults: Optional[MaxResults]


class GetResourceShareAssociationsResponse(TypedDict, total=False):
    resourceShareAssociations: Optional[ResourceShareAssociationList]
    nextToken: Optional[String]


ResourceShareInvitationArnList = List[String]


class GetResourceShareInvitationsRequest(ServiceRequest):
    resourceShareInvitationArns: Optional[ResourceShareInvitationArnList]
    resourceShareArns: Optional[ResourceShareArnList]
    nextToken: Optional[String]
    maxResults: Optional[MaxResults]


ResourceShareInvitationList = List[ResourceShareInvitation]


class GetResourceShareInvitationsResponse(TypedDict, total=False):
    resourceShareInvitations: Optional[ResourceShareInvitationList]
    nextToken: Optional[String]


TagValueList = List[TagValue]


class TagFilter(TypedDict, total=False):
    tagKey: Optional[TagKey]
    tagValues: Optional[TagValueList]


TagFilters = List[TagFilter]


class GetResourceSharesRequest(ServiceRequest):
    resourceShareArns: Optional[ResourceShareArnList]
    resourceShareStatus: Optional[ResourceShareStatus]
    resourceOwner: ResourceOwner
    name: Optional[String]
    tagFilters: Optional[TagFilters]
    nextToken: Optional[String]
    maxResults: Optional[MaxResults]
    permissionArn: Optional[String]
    permissionVersion: Optional[Integer]


ResourceShareList = List[ResourceShare]


class GetResourceSharesResponse(TypedDict, total=False):
    resourceShares: Optional[ResourceShareList]
    nextToken: Optional[String]


class ListPendingInvitationResourcesRequest(ServiceRequest):
    resourceShareInvitationArn: String
    nextToken: Optional[String]
    maxResults: Optional[MaxResults]
    resourceRegionScope: Optional[ResourceRegionScopeFilter]


Resource = TypedDict(
    "Resource",
    {
        "arn": Optional[String],
        "type": Optional[String],
        "resourceShareArn": Optional[String],
        "resourceGroupArn": Optional[String],
        "status": Optional[ResourceStatus],
        "statusMessage": Optional[String],
        "creationTime": Optional[DateTime],
        "lastUpdatedTime": Optional[DateTime],
        "resourceRegionScope": Optional[ResourceRegionScope],
    },
    total=False,
)
ResourceList = List[Resource]


class ListPendingInvitationResourcesResponse(TypedDict, total=False):
    resources: Optional[ResourceList]
    nextToken: Optional[String]


class ListPermissionAssociationsRequest(ServiceRequest):
    permissionArn: Optional[String]
    permissionVersion: Optional[Integer]
    associationStatus: Optional[ResourceShareAssociationStatus]
    resourceType: Optional[String]
    featureSet: Optional[PermissionFeatureSet]
    defaultVersion: Optional[Boolean]
    nextToken: Optional[String]
    maxResults: Optional[MaxResults]


class ListPermissionAssociationsResponse(TypedDict, total=False):
    permissions: Optional[AssociatedPermissionList]
    nextToken: Optional[String]


class ListPermissionVersionsRequest(ServiceRequest):
    permissionArn: String
    nextToken: Optional[String]
    maxResults: Optional[MaxResults]


ResourceSharePermissionList = List[ResourceSharePermissionSummary]


class ListPermissionVersionsResponse(TypedDict, total=False):
    permissions: Optional[ResourceSharePermissionList]
    nextToken: Optional[String]


class ListPermissionsRequest(ServiceRequest):
    resourceType: Optional[String]
    nextToken: Optional[String]
    maxResults: Optional[MaxResults]
    permissionType: Optional[PermissionTypeFilter]


class ListPermissionsResponse(TypedDict, total=False):
    permissions: Optional[ResourceSharePermissionList]
    nextToken: Optional[String]


class ListPrincipalsRequest(ServiceRequest):
    resourceOwner: ResourceOwner
    resourceArn: Optional[String]
    principals: Optional[PrincipalArnOrIdList]
    resourceType: Optional[String]
    resourceShareArns: Optional[ResourceShareArnList]
    nextToken: Optional[String]
    maxResults: Optional[MaxResults]


class Principal(TypedDict, total=False):
    id: Optional[String]
    resourceShareArn: Optional[String]
    creationTime: Optional[DateTime]
    lastUpdatedTime: Optional[DateTime]
    external: Optional[Boolean]


PrincipalList = List[Principal]


class ListPrincipalsResponse(TypedDict, total=False):
    principals: Optional[PrincipalList]
    nextToken: Optional[String]


ReplacePermissionAssociationsWorkIdList = List[String]


class ListReplacePermissionAssociationsWorkRequest(ServiceRequest):
    workIds: Optional[ReplacePermissionAssociationsWorkIdList]
    status: Optional[ReplacePermissionAssociationsWorkStatus]
    nextToken: Optional[String]
    maxResults: Optional[MaxResults]


class ReplacePermissionAssociationsWork(TypedDict, total=False):
    id: Optional[String]
    fromPermissionArn: Optional[String]
    fromPermissionVersion: Optional[String]
    toPermissionArn: Optional[String]
    toPermissionVersion: Optional[String]
    status: Optional[ReplacePermissionAssociationsWorkStatus]
    statusMessage: Optional[String]
    creationTime: Optional[DateTime]
    lastUpdatedTime: Optional[DateTime]


ReplacePermissionAssociationsWorkList = List[ReplacePermissionAssociationsWork]


class ListReplacePermissionAssociationsWorkResponse(TypedDict, total=False):
    replacePermissionAssociationsWorks: Optional[ReplacePermissionAssociationsWorkList]
    nextToken: Optional[String]


class ListResourceSharePermissionsRequest(ServiceRequest):
    resourceShareArn: String
    nextToken: Optional[String]
    maxResults: Optional[MaxResults]


class ListResourceSharePermissionsResponse(TypedDict, total=False):
    permissions: Optional[ResourceSharePermissionList]
    nextToken: Optional[String]


class ListResourceTypesRequest(ServiceRequest):
    nextToken: Optional[String]
    maxResults: Optional[MaxResults]
    resourceRegionScope: Optional[ResourceRegionScopeFilter]


class ServiceNameAndResourceType(TypedDict, total=False):
    resourceType: Optional[String]
    serviceName: Optional[String]
    resourceRegionScope: Optional[ResourceRegionScope]


ServiceNameAndResourceTypeList = List[ServiceNameAndResourceType]


class ListResourceTypesResponse(TypedDict, total=False):
    resourceTypes: Optional[ServiceNameAndResourceTypeList]
    nextToken: Optional[String]


class ListResourcesRequest(ServiceRequest):
    resourceOwner: ResourceOwner
    principal: Optional[String]
    resourceType: Optional[String]
    resourceArns: Optional[ResourceArnList]
    resourceShareArns: Optional[ResourceShareArnList]
    nextToken: Optional[String]
    maxResults: Optional[MaxResults]
    resourceRegionScope: Optional[ResourceRegionScopeFilter]


class ListResourcesResponse(TypedDict, total=False):
    resources: Optional[ResourceList]
    nextToken: Optional[String]


class PromotePermissionCreatedFromPolicyRequest(ServiceRequest):
    permissionArn: String
    name: String
    clientToken: Optional[String]


class PromotePermissionCreatedFromPolicyResponse(TypedDict, total=False):
    permission: Optional[ResourceSharePermissionSummary]
    clientToken: Optional[String]


class PromoteResourceShareCreatedFromPolicyRequest(ServiceRequest):
    resourceShareArn: String


class PromoteResourceShareCreatedFromPolicyResponse(TypedDict, total=False):
    returnValue: Optional[Boolean]


class RejectResourceShareInvitationRequest(ServiceRequest):
    resourceShareInvitationArn: String
    clientToken: Optional[String]


class RejectResourceShareInvitationResponse(TypedDict, total=False):
    resourceShareInvitation: Optional[ResourceShareInvitation]
    clientToken: Optional[String]


class ReplacePermissionAssociationsRequest(ServiceRequest):
    fromPermissionArn: String
    fromPermissionVersion: Optional[Integer]
    toPermissionArn: String
    clientToken: Optional[String]


class ReplacePermissionAssociationsResponse(TypedDict, total=False):
    replacePermissionAssociationsWork: Optional[ReplacePermissionAssociationsWork]
    clientToken: Optional[String]


class SetDefaultPermissionVersionRequest(ServiceRequest):
    permissionArn: String
    permissionVersion: Integer
    clientToken: Optional[String]


class SetDefaultPermissionVersionResponse(TypedDict, total=False):
    returnValue: Optional[Boolean]
    clientToken: Optional[String]


TagKeyList = List[TagKey]


class TagResourceRequest(ServiceRequest):
    resourceShareArn: Optional[String]
    tags: TagList
    resourceArn: Optional[String]


class TagResourceResponse(TypedDict, total=False):
    pass


class UntagResourceRequest(ServiceRequest):
    resourceShareArn: Optional[String]
    tagKeys: TagKeyList
    resourceArn: Optional[String]


class UntagResourceResponse(TypedDict, total=False):
    pass


class UpdateResourceShareRequest(ServiceRequest):
    resourceShareArn: String
    name: Optional[String]
    allowExternalPrincipals: Optional[Boolean]
    clientToken: Optional[String]


class UpdateResourceShareResponse(TypedDict, total=False):
    resourceShare: Optional[ResourceShare]
    clientToken: Optional[String]


class RamApi:
    service = "ram"
    version = "2018-01-04"

    @handler("AcceptResourceShareInvitation")
    def accept_resource_share_invitation(
        self,
        context: RequestContext,
        resource_share_invitation_arn: String,
        client_token: String = None,
    ) -> AcceptResourceShareInvitationResponse:
        raise NotImplementedError

    @handler("AssociateResourceShare")
    def associate_resource_share(
        self,
        context: RequestContext,
        resource_share_arn: String,
        resource_arns: ResourceArnList = None,
        principals: PrincipalArnOrIdList = None,
        client_token: String = None,
        sources: SourceArnOrAccountList = None,
    ) -> AssociateResourceShareResponse:
        raise NotImplementedError

    @handler("AssociateResourceSharePermission")
    def associate_resource_share_permission(
        self,
        context: RequestContext,
        resource_share_arn: String,
        permission_arn: String,
        replace: Boolean = None,
        client_token: String = None,
        permission_version: Integer = None,
    ) -> AssociateResourceSharePermissionResponse:
        raise NotImplementedError

    @handler("CreatePermission")
    def create_permission(
        self,
        context: RequestContext,
        name: PermissionName,
        resource_type: String,
        policy_template: Policy,
        client_token: String = None,
        tags: TagList = None,
    ) -> CreatePermissionResponse:
        raise NotImplementedError

    @handler("CreatePermissionVersion")
    def create_permission_version(
        self,
        context: RequestContext,
        permission_arn: String,
        policy_template: Policy,
        client_token: String = None,
    ) -> CreatePermissionVersionResponse:
        raise NotImplementedError

    @handler("CreateResourceShare")
    def create_resource_share(
        self,
        context: RequestContext,
        name: String,
        resource_arns: ResourceArnList = None,
        principals: PrincipalArnOrIdList = None,
        tags: TagList = None,
        allow_external_principals: Boolean = None,
        client_token: String = None,
        permission_arns: PermissionArnList = None,
        sources: SourceArnOrAccountList = None,
    ) -> CreateResourceShareResponse:
        raise NotImplementedError

    @handler("DeletePermission")
    def delete_permission(
        self, context: RequestContext, permission_arn: String, client_token: String = None
    ) -> DeletePermissionResponse:
        raise NotImplementedError

    @handler("DeletePermissionVersion")
    def delete_permission_version(
        self,
        context: RequestContext,
        permission_arn: String,
        permission_version: Integer,
        client_token: String = None,
    ) -> DeletePermissionVersionResponse:
        raise NotImplementedError

    @handler("DeleteResourceShare")
    def delete_resource_share(
        self, context: RequestContext, resource_share_arn: String, client_token: String = None
    ) -> DeleteResourceShareResponse:
        raise NotImplementedError

    @handler("DisassociateResourceShare")
    def disassociate_resource_share(
        self,
        context: RequestContext,
        resource_share_arn: String,
        resource_arns: ResourceArnList = None,
        principals: PrincipalArnOrIdList = None,
        client_token: String = None,
        sources: SourceArnOrAccountList = None,
    ) -> DisassociateResourceShareResponse:
        raise NotImplementedError

    @handler("DisassociateResourceSharePermission")
    def disassociate_resource_share_permission(
        self,
        context: RequestContext,
        resource_share_arn: String,
        permission_arn: String,
        client_token: String = None,
    ) -> DisassociateResourceSharePermissionResponse:
        raise NotImplementedError

    @handler("EnableSharingWithAwsOrganization")
    def enable_sharing_with_aws_organization(
        self,
        context: RequestContext,
    ) -> EnableSharingWithAwsOrganizationResponse:
        raise NotImplementedError

    @handler("GetPermission")
    def get_permission(
        self, context: RequestContext, permission_arn: String, permission_version: Integer = None
    ) -> GetPermissionResponse:
        raise NotImplementedError

    @handler("GetResourcePolicies")
    def get_resource_policies(
        self,
        context: RequestContext,
        resource_arns: ResourceArnList,
        principal: String = None,
        next_token: String = None,
        max_results: MaxResults = None,
    ) -> GetResourcePoliciesResponse:
        raise NotImplementedError

    @handler("GetResourceShareAssociations")
    def get_resource_share_associations(
        self,
        context: RequestContext,
        association_type: ResourceShareAssociationType,
        resource_share_arns: ResourceShareArnList = None,
        resource_arn: String = None,
        principal: String = None,
        association_status: ResourceShareAssociationStatus = None,
        next_token: String = None,
        max_results: MaxResults = None,
    ) -> GetResourceShareAssociationsResponse:
        raise NotImplementedError

    @handler("GetResourceShareInvitations")
    def get_resource_share_invitations(
        self,
        context: RequestContext,
        resource_share_invitation_arns: ResourceShareInvitationArnList = None,
        resource_share_arns: ResourceShareArnList = None,
        next_token: String = None,
        max_results: MaxResults = None,
    ) -> GetResourceShareInvitationsResponse:
        raise NotImplementedError

    @handler("GetResourceShares")
    def get_resource_shares(
        self,
        context: RequestContext,
        resource_owner: ResourceOwner,
        resource_share_arns: ResourceShareArnList = None,
        resource_share_status: ResourceShareStatus = None,
        name: String = None,
        tag_filters: TagFilters = None,
        next_token: String = None,
        max_results: MaxResults = None,
        permission_arn: String = None,
        permission_version: Integer = None,
    ) -> GetResourceSharesResponse:
        raise NotImplementedError

    @handler("ListPendingInvitationResources")
    def list_pending_invitation_resources(
        self,
        context: RequestContext,
        resource_share_invitation_arn: String,
        next_token: String = None,
        max_results: MaxResults = None,
        resource_region_scope: ResourceRegionScopeFilter = None,
    ) -> ListPendingInvitationResourcesResponse:
        raise NotImplementedError

    @handler("ListPermissionAssociations")
    def list_permission_associations(
        self,
        context: RequestContext,
        permission_arn: String = None,
        permission_version: Integer = None,
        association_status: ResourceShareAssociationStatus = None,
        resource_type: String = None,
        feature_set: PermissionFeatureSet = None,
        default_version: Boolean = None,
        next_token: String = None,
        max_results: MaxResults = None,
    ) -> ListPermissionAssociationsResponse:
        raise NotImplementedError

    @handler("ListPermissionVersions")
    def list_permission_versions(
        self,
        context: RequestContext,
        permission_arn: String,
        next_token: String = None,
        max_results: MaxResults = None,
    ) -> ListPermissionVersionsResponse:
        raise NotImplementedError

    @handler("ListPermissions")
    def list_permissions(
        self,
        context: RequestContext,
        resource_type: String = None,
        next_token: String = None,
        max_results: MaxResults = None,
        permission_type: PermissionTypeFilter = None,
    ) -> ListPermissionsResponse:
        raise NotImplementedError

    @handler("ListPrincipals")
    def list_principals(
        self,
        context: RequestContext,
        resource_owner: ResourceOwner,
        resource_arn: String = None,
        principals: PrincipalArnOrIdList = None,
        resource_type: String = None,
        resource_share_arns: ResourceShareArnList = None,
        next_token: String = None,
        max_results: MaxResults = None,
    ) -> ListPrincipalsResponse:
        raise NotImplementedError

    @handler("ListReplacePermissionAssociationsWork")
    def list_replace_permission_associations_work(
        self,
        context: RequestContext,
        work_ids: ReplacePermissionAssociationsWorkIdList = None,
        status: ReplacePermissionAssociationsWorkStatus = None,
        next_token: String = None,
        max_results: MaxResults = None,
    ) -> ListReplacePermissionAssociationsWorkResponse:
        raise NotImplementedError

    @handler("ListResourceSharePermissions")
    def list_resource_share_permissions(
        self,
        context: RequestContext,
        resource_share_arn: String,
        next_token: String = None,
        max_results: MaxResults = None,
    ) -> ListResourceSharePermissionsResponse:
        raise NotImplementedError

    @handler("ListResourceTypes")
    def list_resource_types(
        self,
        context: RequestContext,
        next_token: String = None,
        max_results: MaxResults = None,
        resource_region_scope: ResourceRegionScopeFilter = None,
    ) -> ListResourceTypesResponse:
        raise NotImplementedError

    @handler("ListResources")
    def list_resources(
        self,
        context: RequestContext,
        resource_owner: ResourceOwner,
        principal: String = None,
        resource_type: String = None,
        resource_arns: ResourceArnList = None,
        resource_share_arns: ResourceShareArnList = None,
        next_token: String = None,
        max_results: MaxResults = None,
        resource_region_scope: ResourceRegionScopeFilter = None,
    ) -> ListResourcesResponse:
        raise NotImplementedError

    @handler("PromotePermissionCreatedFromPolicy")
    def promote_permission_created_from_policy(
        self,
        context: RequestContext,
        permission_arn: String,
        name: String,
        client_token: String = None,
    ) -> PromotePermissionCreatedFromPolicyResponse:
        raise NotImplementedError

    @handler("PromoteResourceShareCreatedFromPolicy")
    def promote_resource_share_created_from_policy(
        self, context: RequestContext, resource_share_arn: String
    ) -> PromoteResourceShareCreatedFromPolicyResponse:
        raise NotImplementedError

    @handler("RejectResourceShareInvitation")
    def reject_resource_share_invitation(
        self,
        context: RequestContext,
        resource_share_invitation_arn: String,
        client_token: String = None,
    ) -> RejectResourceShareInvitationResponse:
        raise NotImplementedError

    @handler("ReplacePermissionAssociations")
    def replace_permission_associations(
        self,
        context: RequestContext,
        from_permission_arn: String,
        to_permission_arn: String,
        from_permission_version: Integer = None,
        client_token: String = None,
    ) -> ReplacePermissionAssociationsResponse:
        raise NotImplementedError

    @handler("SetDefaultPermissionVersion")
    def set_default_permission_version(
        self,
        context: RequestContext,
        permission_arn: String,
        permission_version: Integer,
        client_token: String = None,
    ) -> SetDefaultPermissionVersionResponse:
        raise NotImplementedError

    @handler("TagResource")
    def tag_resource(
        self,
        context: RequestContext,
        tags: TagList,
        resource_share_arn: String = None,
        resource_arn: String = None,
    ) -> TagResourceResponse:
        raise NotImplementedError

    @handler("UntagResource")
    def untag_resource(
        self,
        context: RequestContext,
        tag_keys: TagKeyList,
        resource_share_arn: String = None,
        resource_arn: String = None,
    ) -> UntagResourceResponse:
        raise NotImplementedError

    @handler("UpdateResourceShare")
    def update_resource_share(
        self,
        context: RequestContext,
        resource_share_arn: String,
        name: String = None,
        allow_external_principals: Boolean = None,
        client_token: String = None,
    ) -> UpdateResourceShareResponse:
        raise NotImplementedError
