import sys
from datetime import datetime
from typing import List, Optional

if sys.version_info >= (3, 8):
    from typing import TypedDict
else:
    from typing_extensions import TypedDict

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
    """The operation failed because the client token input parameter matched
    one that was used with a previous call to the operation, but at least
    one of the other input parameters is different from the previous call.
    """

    code: str = "IdempotentParameterMismatchException"
    sender_fault: bool = False
    status_code: int = 400


class InvalidClientTokenException(ServiceException):
    """The operation failed because the specified client token isn't valid."""

    code: str = "InvalidClientTokenException"
    sender_fault: bool = False
    status_code: int = 400


class InvalidMaxResultsException(ServiceException):
    """The operation failed because the specified value for ``MaxResults``
    isn't valid.
    """

    code: str = "InvalidMaxResultsException"
    sender_fault: bool = False
    status_code: int = 400


class InvalidNextTokenException(ServiceException):
    """The operation failed because the specified value for ``NextToken`` isn't
    valid. You must specify a value you received in the ``NextToken``
    response of a previous call to this operation.
    """

    code: str = "InvalidNextTokenException"
    sender_fault: bool = False
    status_code: int = 400


class InvalidParameterException(ServiceException):
    """The operation failed because a parameter you specified isn't valid."""

    code: str = "InvalidParameterException"
    sender_fault: bool = False
    status_code: int = 400


class InvalidPolicyException(ServiceException):
    """The operation failed because a policy you specified isn't valid."""

    code: str = "InvalidPolicyException"
    sender_fault: bool = False
    status_code: int = 400


class InvalidResourceTypeException(ServiceException):
    """The operation failed because the specified resource type isn't valid."""

    code: str = "InvalidResourceTypeException"
    sender_fault: bool = False
    status_code: int = 400


class InvalidStateTransitionException(ServiceException):
    """The operation failed because the requested operation isn't valid for the
    resource share in its current state.
    """

    code: str = "InvalidStateTransitionException"
    sender_fault: bool = False
    status_code: int = 400


class MalformedArnException(ServiceException):
    """The operation failed because the specified `Amazon Resource Name
    (ARN) <https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html>`__
    has a format that isn't valid.
    """

    code: str = "MalformedArnException"
    sender_fault: bool = False
    status_code: int = 400


class MalformedPolicyTemplateException(ServiceException):
    """The operation failed because the policy template that you provided isn't
    valid.
    """

    code: str = "MalformedPolicyTemplateException"
    sender_fault: bool = False
    status_code: int = 400


class MissingRequiredParameterException(ServiceException):
    """The operation failed because a required input parameter is missing."""

    code: str = "MissingRequiredParameterException"
    sender_fault: bool = False
    status_code: int = 400


class OperationNotPermittedException(ServiceException):
    """The operation failed because the requested operation isn't permitted."""

    code: str = "OperationNotPermittedException"
    sender_fault: bool = False
    status_code: int = 400


class PermissionAlreadyExistsException(ServiceException):
    """The operation failed because a permission with the specified name
    already exists in the requested Amazon Web Services Region. Choose a
    different name.
    """

    code: str = "PermissionAlreadyExistsException"
    sender_fault: bool = False
    status_code: int = 409


class PermissionLimitExceededException(ServiceException):
    """The operation failed because it would exceed the maximum number of
    permissions you can create in each Amazon Web Services Region. To view
    the limits for your Amazon Web Services account, see the `RAM page in
    the Service Quotas
    console <https://console.aws.amazon.com/servicequotas/home/services/ram/quotas>`__.
    """

    code: str = "PermissionLimitExceededException"
    sender_fault: bool = False
    status_code: int = 400


class PermissionVersionsLimitExceededException(ServiceException):
    """The operation failed because it would exceed the limit for the number of
    versions you can have for a permission. To view the limits for your
    Amazon Web Services account, see the `RAM page in the Service Quotas
    console <https://console.aws.amazon.com/servicequotas/home/services/ram/quotas>`__.
    """

    code: str = "PermissionVersionsLimitExceededException"
    sender_fault: bool = False
    status_code: int = 400


class ResourceArnNotFoundException(ServiceException):
    """The operation failed because the specified `Amazon Resource Name
    (ARN) <https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html>`__
    was not found.
    """

    code: str = "ResourceArnNotFoundException"
    sender_fault: bool = False
    status_code: int = 400


class ResourceShareInvitationAlreadyAcceptedException(ServiceException):
    """The operation failed because the specified invitation was already
    accepted.
    """

    code: str = "ResourceShareInvitationAlreadyAcceptedException"
    sender_fault: bool = False
    status_code: int = 400


class ResourceShareInvitationAlreadyRejectedException(ServiceException):
    """The operation failed because the specified invitation was already
    rejected.
    """

    code: str = "ResourceShareInvitationAlreadyRejectedException"
    sender_fault: bool = False
    status_code: int = 400


class ResourceShareInvitationArnNotFoundException(ServiceException):
    """The operation failed because the specified `Amazon Resource Name
    (ARN) <https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html>`__
    for an invitation was not found.
    """

    code: str = "ResourceShareInvitationArnNotFoundException"
    sender_fault: bool = False
    status_code: int = 400


class ResourceShareInvitationExpiredException(ServiceException):
    """The operation failed because the specified invitation is past its
    expiration date and time.
    """

    code: str = "ResourceShareInvitationExpiredException"
    sender_fault: bool = False
    status_code: int = 400


class ResourceShareLimitExceededException(ServiceException):
    """The operation failed because it would exceed the limit for resource
    shares for your account. To view the limits for your Amazon Web Services
    account, see the `RAM page in the Service Quotas
    console <https://console.aws.amazon.com/servicequotas/home/services/ram/quotas>`__.
    """

    code: str = "ResourceShareLimitExceededException"
    sender_fault: bool = False
    status_code: int = 400


class ServerInternalException(ServiceException):
    """The operation failed because the service could not respond to the
    request due to an internal problem. Try again later.
    """

    code: str = "ServerInternalException"
    sender_fault: bool = False
    status_code: int = 500


class ServiceUnavailableException(ServiceException):
    """The operation failed because the service isn't available. Try again
    later.
    """

    code: str = "ServiceUnavailableException"
    sender_fault: bool = False
    status_code: int = 503


class TagLimitExceededException(ServiceException):
    """The operation failed because it would exceed the limit for tags for your
    Amazon Web Services account.
    """

    code: str = "TagLimitExceededException"
    sender_fault: bool = False
    status_code: int = 400


class TagPolicyViolationException(ServiceException):
    """The operation failed because the specified tag key is a reserved word
    and can't be used.
    """

    code: str = "TagPolicyViolationException"
    sender_fault: bool = False
    status_code: int = 400


class ThrottlingException(ServiceException):
    """The operation failed because it exceeded the rate at which you are
    allowed to perform this operation. Please try again later.
    """

    code: str = "ThrottlingException"
    sender_fault: bool = False
    status_code: int = 429


class UnknownResourceException(ServiceException):
    """The operation failed because a specified resource couldn't be found."""

    code: str = "UnknownResourceException"
    sender_fault: bool = False
    status_code: int = 400


class UnmatchedPolicyPermissionException(ServiceException):
    """There isn't an existing managed permission defined in RAM that has the
    same IAM permissions as the resource-based policy attached to the
    resource. You should first run PromotePermissionCreatedFromPolicy to
    create that managed permission.
    """

    code: str = "UnmatchedPolicyPermissionException"
    sender_fault: bool = False
    status_code: int = 400


class AcceptResourceShareInvitationRequest(ServiceRequest):
    resourceShareInvitationArn: String
    clientToken: Optional[String]


DateTime = datetime


class ResourceShareAssociation(TypedDict, total=False):
    """Describes an association between a resource share and either a principal
    or a resource.
    """

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
    """Describes an invitation for an Amazon Web Services account to join a
    resource share.
    """

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
    """An object that describes a managed permission associated with a resource
    share.
    """

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
    """A structure containing a tag. A tag is metadata that you can attach to
    your resources to help organize and categorize them. You can also use
    them to help you secure your resources. For more information, see
    `Controlling access to Amazon Web Services resources using
    tags <https://docs.aws.amazon.com/IAM/latest/UserGuide/access_tags.html>`__.

    For more information about tags, see `Tagging Amazon Web Services
    resources <https://docs.aws.amazon.com/general/latest/gr/aws_tagging.html>`__
    in the *Amazon Web Services General Reference Guide*.
    """

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
    """Information about an RAM permission."""

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
    """Information about a RAM managed permission."""

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
    """Describes a resource share in RAM."""

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
    """A tag key and optional list of possible values that you can use to
    filter results for tagged resources.
    """

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
    """Describes a principal for use with Resource Access Manager."""

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
    """A structure that represents the background work that RAM performs when
    you invoke the ReplacePermissionAssociations operation.
    """

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
    """Information about a shareable resource type and the Amazon Web Services
    service to which resources of that type belong.
    """

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
        """Accepts an invitation to a resource share from another Amazon Web
        Services account. After you accept the invitation, the resources
        included in the resource share are available to interact with in the
        relevant Amazon Web Services Management Consoles and tools.

        :param resource_share_invitation_arn: The `Amazon Resource Name
        (ARN) <https://docs.
        :param client_token: Specifies a unique, case-sensitive identifier that you provide to ensure
        the idempotency of the request.
        :returns: AcceptResourceShareInvitationResponse
        :raises MalformedArnException:
        :raises OperationNotPermittedException:
        :raises ResourceShareInvitationArnNotFoundException:
        :raises ResourceShareInvitationAlreadyAcceptedException:
        :raises ResourceShareInvitationAlreadyRejectedException:
        :raises ResourceShareInvitationExpiredException:
        :raises ServerInternalException:
        :raises ServiceUnavailableException:
        :raises InvalidClientTokenException:
        :raises IdempotentParameterMismatchException:
        """
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
        """Adds the specified list of principals and list of resources to a
        resource share. Principals that already have access to this resource
        share immediately receive access to the added resources. Newly added
        principals immediately receive access to the resources shared in this
        resource share.

        :param resource_share_arn: Specifies the `Amazon Resource Name
        (ARN) <https://docs.
        :param resource_arns: Specifies a list of `Amazon Resource Names
        (ARNs) <https://docs.
        :param principals: Specifies a list of principals to whom you want to the resource share.
        :param client_token: Specifies a unique, case-sensitive identifier that you provide to ensure
        the idempotency of the request.
        :param sources: Specifies from which source accounts the service principal has access to
        the resources in this resource share.
        :returns: AssociateResourceShareResponse
        :raises IdempotentParameterMismatchException:
        :raises UnknownResourceException:
        :raises InvalidStateTransitionException:
        :raises ResourceShareLimitExceededException:
        :raises MalformedArnException:
        :raises InvalidStateTransitionException:
        :raises InvalidClientTokenException:
        :raises InvalidParameterException:
        :raises OperationNotPermittedException:
        :raises ServerInternalException:
        :raises ServiceUnavailableException:
        :raises UnknownResourceException:
        :raises ThrottlingException:
        """
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
        """Adds or replaces the RAM permission for a resource type included in a
        resource share. You can have exactly one permission associated with each
        resource type in the resource share. You can add a new RAM permission
        only if there are currently no resources of that resource type currently
        in the resource share.

        :param resource_share_arn: Specifies the `Amazon Resource Name
        (ARN) <https://docs.
        :param permission_arn: Specifies the `Amazon Resource Name
        (ARN) <https://docs.
        :param replace: Specifies whether the specified permission should replace the existing
        permission associated with the resource share.
        :param client_token: Specifies a unique, case-sensitive identifier that you provide to ensure
        the idempotency of the request.
        :param permission_version: Specifies the version of the RAM permission to associate with the
        resource share.
        :returns: AssociateResourceSharePermissionResponse
        :raises MalformedArnException:
        :raises UnknownResourceException:
        :raises InvalidParameterException:
        :raises InvalidClientTokenException:
        :raises ServerInternalException:
        :raises ServiceUnavailableException:
        :raises OperationNotPermittedException:
        """
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
        """Creates a customer managed permission for a specified resource type that
        you can attach to resource shares. It is created in the Amazon Web
        Services Region in which you call the operation.

        :param name: Specifies the name of the customer managed permission.
        :param resource_type: Specifies the name of the resource type that this customer managed
        permission applies to.
        :param policy_template: A string in JSON format string that contains the following elements of a
        resource-based policy:

        -  **Effect**: must be set to ``ALLOW``.
        :param client_token: Specifies a unique, case-sensitive identifier that you provide to ensure
        the idempotency of the request.
        :param tags: Specifies a list of one or more tag key and value pairs to attach to the
        permission.
        :returns: CreatePermissionResponse
        :raises InvalidParameterException:
        :raises InvalidPolicyException:
        :raises OperationNotPermittedException:
        :raises ServerInternalException:
        :raises ServiceUnavailableException:
        :raises PermissionAlreadyExistsException:
        :raises MalformedPolicyTemplateException:
        :raises InvalidClientTokenException:
        :raises PermissionLimitExceededException:
        :raises IdempotentParameterMismatchException:
        """
        raise NotImplementedError

    @handler("CreatePermissionVersion")
    def create_permission_version(
        self,
        context: RequestContext,
        permission_arn: String,
        policy_template: Policy,
        client_token: String = None,
    ) -> CreatePermissionVersionResponse:
        """Creates a new version of the specified customer managed permission. The
        new version is automatically set as the default version of the customer
        managed permission. New resource shares automatically use the default
        permission. Existing resource shares continue to use their original
        permission versions, but you can use ReplacePermissionAssociations to
        update them.

        If the specified customer managed permission already has the maximum of
        5 versions, then you must delete one of the existing versions before you
        can create a new one.

        :param permission_arn: Specifies the `Amazon Resource Name
        (ARN) <https://docs.
        :param policy_template: A string in JSON format string that contains the following elements of a
        resource-based policy:

        -  **Effect**: must be set to ``ALLOW``.
        :param client_token: Specifies a unique, case-sensitive identifier that you provide to ensure
        the idempotency of the request.
        :returns: CreatePermissionVersionResponse
        :raises InvalidParameterException:
        :raises InvalidPolicyException:
        :raises ServerInternalException:
        :raises ServiceUnavailableException:
        :raises UnknownResourceException:
        :raises MalformedPolicyTemplateException:
        :raises MalformedArnException:
        :raises InvalidClientTokenException:
        :raises IdempotentParameterMismatchException:
        :raises PermissionVersionsLimitExceededException:
        """
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
        """Creates a resource share. You can provide a list of the `Amazon Resource
        Names
        (ARNs) <https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html>`__
        for the resources that you want to share, a list of principals you want
        to share the resources with, and the permissions to grant those
        principals.

        Sharing a resource makes it available for use by principals outside of
        the Amazon Web Services account that created the resource. Sharing
        doesn't change any permissions or quotas that apply to the resource in
        the account that created it.

        :param name: Specifies the name of the resource share.
        :param resource_arns: Specifies a list of one or more ARNs of the resources to associate with
        the resource share.
        :param principals: Specifies a list of one or more principals to associate with the
        resource share.
        :param tags: Specifies one or more tags to attach to the resource share itself.
        :param allow_external_principals: Specifies whether principals outside your organization in Organizations
        can be associated with a resource share.
        :param client_token: Specifies a unique, case-sensitive identifier that you provide to ensure
        the idempotency of the request.
        :param permission_arns: Specifies the `Amazon Resource Names
        (ARNs) <https://docs.
        :param sources: Specifies from which source accounts the service principal has access to
        the resources in this resource share.
        :returns: CreateResourceShareResponse
        :raises IdempotentParameterMismatchException:
        :raises InvalidStateTransitionException:
        :raises UnknownResourceException:
        :raises MalformedArnException:
        :raises InvalidClientTokenException:
        :raises InvalidParameterException:
        :raises OperationNotPermittedException:
        :raises ResourceShareLimitExceededException:
        :raises TagPolicyViolationException:
        :raises TagLimitExceededException:
        :raises ServerInternalException:
        :raises ServiceUnavailableException:
        """
        raise NotImplementedError

    @handler("DeletePermission")
    def delete_permission(
        self, context: RequestContext, permission_arn: String, client_token: String = None
    ) -> DeletePermissionResponse:
        """Deletes the specified customer managed permission in the Amazon Web
        Services Region in which you call this operation. You can delete a
        customer managed permission only if it isn't attached to any resource
        share. The operation deletes all versions associated with the customer
        managed permission.

        :param permission_arn: Specifies the `Amazon Resource Name
        (ARN) <https://docs.
        :param client_token: Specifies a unique, case-sensitive identifier that you provide to ensure
        the idempotency of the request.
        :returns: DeletePermissionResponse
        :raises MalformedArnException:
        :raises ServerInternalException:
        :raises ServiceUnavailableException:
        :raises OperationNotPermittedException:
        :raises UnknownResourceException:
        :raises InvalidClientTokenException:
        :raises IdempotentParameterMismatchException:
        """
        raise NotImplementedError

    @handler("DeletePermissionVersion")
    def delete_permission_version(
        self,
        context: RequestContext,
        permission_arn: String,
        permission_version: Integer,
        client_token: String = None,
    ) -> DeletePermissionVersionResponse:
        """Deletes one version of a customer managed permission. The version you
        specify must not be attached to any resource share and must not be the
        default version for the permission.

        If a customer managed permission has the maximum of 5 versions, then you
        must delete at least one version before you can create another.

        :param permission_arn: Specifies the `Amazon Resource Name
        (ARN) <https://docs.
        :param permission_version: Specifies the version number to delete.
        :param client_token: Specifies a unique, case-sensitive identifier that you provide to ensure
        the idempotency of the request.
        :returns: DeletePermissionVersionResponse
        :raises MalformedArnException:
        :raises InvalidParameterException:
        :raises ServerInternalException:
        :raises ServiceUnavailableException:
        :raises OperationNotPermittedException:
        :raises UnknownResourceException:
        :raises InvalidClientTokenException:
        :raises IdempotentParameterMismatchException:
        """
        raise NotImplementedError

    @handler("DeleteResourceShare")
    def delete_resource_share(
        self, context: RequestContext, resource_share_arn: String, client_token: String = None
    ) -> DeleteResourceShareResponse:
        """Deletes the specified resource share.

        This doesn't delete any of the resources that were associated with the
        resource share; it only stops the sharing of those resources through
        this resource share.

        :param resource_share_arn: Specifies the `Amazon Resource Name
        (ARN) <https://docs.
        :param client_token: Specifies a unique, case-sensitive identifier that you provide to ensure
        the idempotency of the request.
        :returns: DeleteResourceShareResponse
        :raises OperationNotPermittedException:
        :raises IdempotentParameterMismatchException:
        :raises InvalidStateTransitionException:
        :raises UnknownResourceException:
        :raises MalformedArnException:
        :raises InvalidClientTokenException:
        :raises InvalidParameterException:
        :raises ServerInternalException:
        :raises ServiceUnavailableException:
        """
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
        """Removes the specified principals or resources from participating in the
        specified resource share.

        :param resource_share_arn: Specifies `Amazon Resource Name
        (ARN) <https://docs.
        :param resource_arns: Specifies a list of `Amazon Resource Names
        (ARNs) <https://docs.
        :param principals: Specifies a list of one or more principals that no longer are to have
        access to the resources in this resource share.
        :param client_token: Specifies a unique, case-sensitive identifier that you provide to ensure
        the idempotency of the request.
        :param sources: Specifies from which source accounts the service principal no longer has
        access to the resources in this resource share.
        :returns: DisassociateResourceShareResponse
        :raises IdempotentParameterMismatchException:
        :raises ResourceShareLimitExceededException:
        :raises MalformedArnException:
        :raises InvalidStateTransitionException:
        :raises InvalidClientTokenException:
        :raises InvalidParameterException:
        :raises OperationNotPermittedException:
        :raises ServerInternalException:
        :raises ServiceUnavailableException:
        :raises UnknownResourceException:
        """
        raise NotImplementedError

    @handler("DisassociateResourceSharePermission")
    def disassociate_resource_share_permission(
        self,
        context: RequestContext,
        resource_share_arn: String,
        permission_arn: String,
        client_token: String = None,
    ) -> DisassociateResourceSharePermissionResponse:
        """Removes a managed permission from a resource share. Permission changes
        take effect immediately. You can remove a managed permission from a
        resource share only if there are currently no resources of the relevant
        resource type currently attached to the resource share.

        :param resource_share_arn: The `Amazon Resource Name
        (ARN) <https://docs.
        :param permission_arn: The `Amazon Resource Name
        (ARN) <https://docs.
        :param client_token: Specifies a unique, case-sensitive identifier that you provide to ensure
        the idempotency of the request.
        :returns: DisassociateResourceSharePermissionResponse
        :raises MalformedArnException:
        :raises UnknownResourceException:
        :raises InvalidParameterException:
        :raises InvalidClientTokenException:
        :raises ServerInternalException:
        :raises ServiceUnavailableException:
        :raises OperationNotPermittedException:
        :raises InvalidStateTransitionException:
        """
        raise NotImplementedError

    @handler("EnableSharingWithAwsOrganization")
    def enable_sharing_with_aws_organization(
        self,
        context: RequestContext,
    ) -> EnableSharingWithAwsOrganizationResponse:
        """Enables resource sharing within your organization in Organizations. This
        operation creates a service-linked role called
        ``AWSServiceRoleForResourceAccessManager`` that has the IAM managed
        policy named AWSResourceAccessManagerServiceRolePolicy attached. This
        role permits RAM to retrieve information about the organization and its
        structure. This lets you share resources with all of the accounts in the
        calling account's organization by specifying the organization ID, or all
        of the accounts in an organizational unit (OU) by specifying the OU ID.
        Until you enable sharing within the organization, you can specify only
        individual Amazon Web Services accounts, or for supported resource
        types, IAM roles and users.

        You must call this operation from an IAM role or user in the
        organization's management account.

        :returns: EnableSharingWithAwsOrganizationResponse
        :raises OperationNotPermittedException:
        :raises ServerInternalException:
        :raises ServiceUnavailableException:
        """
        raise NotImplementedError

    @handler("GetPermission")
    def get_permission(
        self, context: RequestContext, permission_arn: String, permission_version: Integer = None
    ) -> GetPermissionResponse:
        """Retrieves the contents of a managed permission in JSON format.

        :param permission_arn: Specifies the `Amazon Resource Name
        (ARN) <https://docs.
        :param permission_version: Specifies the version number of the RAM permission to retrieve.
        :returns: GetPermissionResponse
        :raises InvalidParameterException:
        :raises MalformedArnException:
        :raises UnknownResourceException:
        :raises ServerInternalException:
        :raises ServiceUnavailableException:
        :raises OperationNotPermittedException:
        """
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
        """Retrieves the resource policies for the specified resources that you own
        and have shared.

        :param resource_arns: Specifies the `Amazon Resource Names
        (ARNs) <https://docs.
        :param principal: Specifies the principal.
        :param next_token: Specifies that you want to receive the next page of results.
        :param max_results: Specifies the total number of results that you want included on each
        page of the response.
        :returns: GetResourcePoliciesResponse
        :raises MalformedArnException:
        :raises InvalidNextTokenException:
        :raises InvalidParameterException:
        :raises ResourceArnNotFoundException:
        :raises ServerInternalException:
        :raises ServiceUnavailableException:
        """
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
        """Retrieves the lists of resources and principals that associated for
        resource shares that you own.

        :param association_type: Specifies whether you want to retrieve the associations that involve a
        specified resource or principal.
        :param resource_share_arns: Specifies a list of `Amazon Resource Names
        (ARNs) <https://docs.
        :param resource_arn: Specifies the `Amazon Resource Name
        (ARN) <https://docs.
        :param principal: Specifies the ID of the principal whose resource shares you want to
        retrieve.
        :param association_status: Specifies that you want to retrieve only associations that have this
        status.
        :param next_token: Specifies that you want to receive the next page of results.
        :param max_results: Specifies the total number of results that you want included on each
        page of the response.
        :returns: GetResourceShareAssociationsResponse
        :raises UnknownResourceException:
        :raises MalformedArnException:
        :raises InvalidNextTokenException:
        :raises InvalidParameterException:
        :raises OperationNotPermittedException:
        :raises ServerInternalException:
        :raises ServiceUnavailableException:
        """
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
        """Retrieves details about invitations that you have received for resource
        shares.

        :param resource_share_invitation_arns: Specifies the `Amazon Resource Names
        (ARNs) <https://docs.
        :param resource_share_arns: Specifies that you want details about invitations only for the resource
        shares described by this list of `Amazon Resource Names
        (ARNs) <https://docs.
        :param next_token: Specifies that you want to receive the next page of results.
        :param max_results: Specifies the total number of results that you want included on each
        page of the response.
        :returns: GetResourceShareInvitationsResponse
        :raises ResourceShareInvitationArnNotFoundException:
        :raises InvalidMaxResultsException:
        :raises MalformedArnException:
        :raises UnknownResourceException:
        :raises InvalidNextTokenException:
        :raises InvalidParameterException:
        :raises ServerInternalException:
        :raises ServiceUnavailableException:
        """
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
        """Retrieves details about the resource shares that you own or that are
        shared with you.

        :param resource_owner: Specifies that you want to retrieve details of only those resource
        shares that match the following:

        -  **``SELF``** – resource shares that your account shares with other
           accounts

        -  **``OTHER-ACCOUNTS``** – resource shares that other accounts share
           with your account.
        :param resource_share_arns: Specifies the `Amazon Resource Names
        (ARNs) <https://docs.
        :param resource_share_status: Specifies that you want to retrieve details of only those resource
        shares that have this status.
        :param name: Specifies the name of an individual resource share that you want to
        retrieve details about.
        :param tag_filters: Specifies that you want to retrieve details of only those resource
        shares that match the specified tag keys and values.
        :param next_token: Specifies that you want to receive the next page of results.
        :param max_results: Specifies the total number of results that you want included on each
        page of the response.
        :param permission_arn: Specifies that you want to retrieve details of only those resource
        shares that use the managed permission with this `Amazon Resource Name
        (ARN) <https://docs.
        :param permission_version: Specifies that you want to retrieve details for only those resource
        shares that use the specified version of the managed permission.
        :returns: GetResourceSharesResponse
        :raises UnknownResourceException:
        :raises MalformedArnException:
        :raises InvalidNextTokenException:
        :raises InvalidParameterException:
        :raises ServerInternalException:
        :raises ServiceUnavailableException:
        """
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
        """Lists the resources in a resource share that is shared with you but for
        which the invitation is still ``PENDING``. That means that you haven't
        accepted or rejected the invitation and the invitation hasn't expired.

        :param resource_share_invitation_arn: Specifies the `Amazon Resource Name
        (ARN) <https://docs.
        :param next_token: Specifies that you want to receive the next page of results.
        :param max_results: Specifies the total number of results that you want included on each
        page of the response.
        :param resource_region_scope: Specifies that you want the results to include only resources that have
        the specified scope.
        :returns: ListPendingInvitationResourcesResponse
        :raises MalformedArnException:
        :raises InvalidNextTokenException:
        :raises InvalidParameterException:
        :raises ServerInternalException:
        :raises ServiceUnavailableException:
        :raises ResourceShareInvitationArnNotFoundException:
        :raises MissingRequiredParameterException:
        :raises ResourceShareInvitationAlreadyRejectedException:
        :raises ResourceShareInvitationExpiredException:
        """
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
        """Lists information about the managed permission and its associations to
        any resource shares that use this managed permission. This lets you see
        which resource shares use which versions of the specified managed
        permission.

        :param permission_arn: Specifies the `Amazon Resource Name
        (ARN) <https://docs.
        :param permission_version: Specifies that you want to list only those associations with resource
        shares that use this version of the managed permission.
        :param association_status: Specifies that you want to list only those associations with resource
        shares that match this status.
        :param resource_type: Specifies that you want to list only those associations with resource
        shares that include at least one resource of this resource type.
        :param feature_set: Specifies that you want to list only those associations with resource
        shares that have a ``featureSet`` with this value.
        :param default_version: When ``true``, specifies that you want to list only those associations
        with resource shares that use the default version of the specified
        managed permission.
        :param next_token: Specifies that you want to receive the next page of results.
        :param max_results: Specifies the total number of results that you want included on each
        page of the response.
        :returns: ListPermissionAssociationsResponse
        :raises InvalidParameterException:
        :raises MalformedArnException:
        :raises InvalidNextTokenException:
        :raises ServerInternalException:
        :raises ServiceUnavailableException:
        """
        raise NotImplementedError

    @handler("ListPermissionVersions")
    def list_permission_versions(
        self,
        context: RequestContext,
        permission_arn: String,
        next_token: String = None,
        max_results: MaxResults = None,
    ) -> ListPermissionVersionsResponse:
        """Lists the available versions of the specified RAM permission.

        :param permission_arn: Specifies the `Amazon Resource Name
        (ARN) <https://docs.
        :param next_token: Specifies that you want to receive the next page of results.
        :param max_results: Specifies the total number of results that you want included on each
        page of the response.
        :returns: ListPermissionVersionsResponse
        :raises MalformedArnException:
        :raises UnknownResourceException:
        :raises InvalidNextTokenException:
        :raises ServerInternalException:
        :raises ServiceUnavailableException:
        :raises OperationNotPermittedException:
        :raises InvalidParameterException:
        """
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
        """Retrieves a list of available RAM permissions that you can use for the
        supported resource types.

        :param resource_type: Specifies that you want to list only those permissions that apply to the
        specified resource type.
        :param next_token: Specifies that you want to receive the next page of results.
        :param max_results: Specifies the total number of results that you want included on each
        page of the response.
        :param permission_type: Specifies that you want to list only permissions of this type:

        -  ``AWS`` – returns only Amazon Web Services managed permissions.
        :returns: ListPermissionsResponse
        :raises InvalidParameterException:
        :raises InvalidNextTokenException:
        :raises ServerInternalException:
        :raises ServiceUnavailableException:
        :raises OperationNotPermittedException:
        """
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
        """Lists the principals that you are sharing resources with or that are
        sharing resources with you.

        :param resource_owner: Specifies that you want to list information for only resource shares
        that match the following:

        -  **``SELF``** – principals that your account is sharing resources with

        -  **``OTHER-ACCOUNTS``** – principals that are sharing resources with
           your account.
        :param resource_arn: Specifies that you want to list principal information for the resource
        share with the specified `Amazon Resource Name
        (ARN) <https://docs.
        :param principals: Specifies that you want to list information for only the listed
        principals.
        :param resource_type: Specifies that you want to list information for only principals
        associated with resource shares that include the specified resource
        type.
        :param resource_share_arns: Specifies that you want to list information for only principals
        associated with the resource shares specified by a list the `Amazon
        Resource Names
        (ARNs) <https://docs.
        :param next_token: Specifies that you want to receive the next page of results.
        :param max_results: Specifies the total number of results that you want included on each
        page of the response.
        :returns: ListPrincipalsResponse
        :raises MalformedArnException:
        :raises UnknownResourceException:
        :raises InvalidNextTokenException:
        :raises InvalidParameterException:
        :raises ServerInternalException:
        :raises ServiceUnavailableException:
        """
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
        """Retrieves the current status of the asynchronous tasks performed by RAM
        when you perform the ReplacePermissionAssociationsWork operation.

        :param work_ids: A list of IDs.
        :param status: Specifies that you want to see only the details about requests with a
        status that matches this value.
        :param next_token: Specifies that you want to receive the next page of results.
        :param max_results: Specifies the total number of results that you want included on each
        page of the response.
        :returns: ListReplacePermissionAssociationsWorkResponse
        :raises ServerInternalException:
        :raises ServiceUnavailableException:
        :raises InvalidNextTokenException:
        :raises InvalidParameterException:
        """
        raise NotImplementedError

    @handler("ListResourceSharePermissions")
    def list_resource_share_permissions(
        self,
        context: RequestContext,
        resource_share_arn: String,
        next_token: String = None,
        max_results: MaxResults = None,
    ) -> ListResourceSharePermissionsResponse:
        """Lists the RAM permissions that are associated with a resource share.

        :param resource_share_arn: Specifies the `Amazon Resource Name
        (ARN) <https://docs.
        :param next_token: Specifies that you want to receive the next page of results.
        :param max_results: Specifies the total number of results that you want included on each
        page of the response.
        :returns: ListResourceSharePermissionsResponse
        :raises InvalidParameterException:
        :raises MalformedArnException:
        :raises UnknownResourceException:
        :raises InvalidNextTokenException:
        :raises ServerInternalException:
        :raises ServiceUnavailableException:
        :raises OperationNotPermittedException:
        """
        raise NotImplementedError

    @handler("ListResourceTypes")
    def list_resource_types(
        self,
        context: RequestContext,
        next_token: String = None,
        max_results: MaxResults = None,
        resource_region_scope: ResourceRegionScopeFilter = None,
    ) -> ListResourceTypesResponse:
        """Lists the resource types that can be shared by RAM.

        :param next_token: Specifies that you want to receive the next page of results.
        :param max_results: Specifies the total number of results that you want included on each
        page of the response.
        :param resource_region_scope: Specifies that you want the results to include only resources that have
        the specified scope.
        :returns: ListResourceTypesResponse
        :raises InvalidNextTokenException:
        :raises InvalidParameterException:
        :raises ServerInternalException:
        :raises ServiceUnavailableException:
        """
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
        """Lists the resources that you added to a resource share or the resources
        that are shared with you.

        :param resource_owner: Specifies that you want to list only the resource shares that match the
        following:

        -  **``SELF``** – resources that your account shares with other accounts

        -  **``OTHER-ACCOUNTS``** – resources that other accounts share with
           your account.
        :param principal: Specifies that you want to list only the resource shares that are
        associated with the specified principal.
        :param resource_type: Specifies that you want to list only the resource shares that include
        resources of the specified resource type.
        :param resource_arns: Specifies that you want to list only the resource shares that include
        resources with the specified `Amazon Resource Names
        (ARNs) <https://docs.
        :param resource_share_arns: Specifies that you want to list only resources in the resource shares
        identified by the specified `Amazon Resource Names
        (ARNs) <https://docs.
        :param next_token: Specifies that you want to receive the next page of results.
        :param max_results: Specifies the total number of results that you want included on each
        page of the response.
        :param resource_region_scope: Specifies that you want the results to include only resources that have
        the specified scope.
        :returns: ListResourcesResponse
        :raises InvalidResourceTypeException:
        :raises UnknownResourceException:
        :raises MalformedArnException:
        :raises InvalidNextTokenException:
        :raises InvalidParameterException:
        :raises ServerInternalException:
        :raises ServiceUnavailableException:
        """
        raise NotImplementedError

    @handler("PromotePermissionCreatedFromPolicy")
    def promote_permission_created_from_policy(
        self,
        context: RequestContext,
        permission_arn: String,
        name: String,
        client_token: String = None,
    ) -> PromotePermissionCreatedFromPolicyResponse:
        """When you attach a resource-based policy to a resource, RAM automatically
        creates a resource share of ``featureSet`` = ``CREATED_FROM_POLICY``
        with a managed permission that has the same IAM permissions as the
        original resource-based policy. However, this type of managed permission
        is visible to only the resource share owner, and the associated resource
        share can't be modified by using RAM.

        This operation creates a separate, fully manageable customer managed
        permission that has the same IAM permissions as the original
        resource-based policy. You can associate this customer managed
        permission to any resource shares.

        Before you use PromoteResourceShareCreatedFromPolicy, you should first
        run this operation to ensure that you have an appropriate customer
        managed permission that can be associated with the promoted resource
        share.

        -  The original ``CREATED_FROM_POLICY`` policy isn't deleted, and
           resource shares using that original policy aren't automatically
           updated.

        -  You can't modify a ``CREATED_FROM_POLICY`` resource share so you
           can't associate the new customer managed permission by using
           ``ReplacePermsissionAssociations``. However, if you use
           PromoteResourceShareCreatedFromPolicy, that operation automatically
           associates the fully manageable customer managed permission to the
           newly promoted ``STANDARD`` resource share.

        -  After you promote a resource share, if the original
           ``CREATED_FROM_POLICY`` managed permission has no other associations
           to A resource share, then RAM automatically deletes it.

        :param permission_arn: Specifies the `Amazon Resource Name
        (ARN) <https://docs.
        :param name: Specifies a name for the promoted customer managed permission.
        :param client_token: Specifies a unique, case-sensitive identifier that you provide to ensure
        the idempotency of the request.
        :returns: PromotePermissionCreatedFromPolicyResponse
        :raises MalformedArnException:
        :raises OperationNotPermittedException:
        :raises InvalidParameterException:
        :raises MissingRequiredParameterException:
        :raises ServerInternalException:
        :raises ServiceUnavailableException:
        :raises UnknownResourceException:
        """
        raise NotImplementedError

    @handler("PromoteResourceShareCreatedFromPolicy")
    def promote_resource_share_created_from_policy(
        self, context: RequestContext, resource_share_arn: String
    ) -> PromoteResourceShareCreatedFromPolicyResponse:
        """When you attach a resource-based policy to a resource, RAM automatically
        creates a resource share of ``featureSet`` = ``CREATED_FROM_POLICY``
        with a managed permission that has the same IAM permissions as the
        original resource-based policy. However, this type of managed permission
        is visible to only the resource share owner, and the associated resource
        share can't be modified by using RAM.

        This operation promotes the resource share to a ``STANDARD`` resource
        share that is fully manageable in RAM. When you promote a resource
        share, you can then manage the resource share in RAM and it becomes
        visible to all of the principals you shared it with.

        Before you perform this operation, you should first run
        PromotePermissionCreatedFromPolicyto ensure that you have an appropriate
        customer managed permission that can be associated with this resource
        share after its is promoted. If this operation can't find a managed
        permission that exactly matches the existing ``CREATED_FROM_POLICY``
        permission, then this operation fails.

        :param resource_share_arn: Specifies the `Amazon Resource Name
        (ARN) <https://docs.
        :returns: PromoteResourceShareCreatedFromPolicyResponse
        :raises MalformedArnException:
        :raises ResourceShareLimitExceededException:
        :raises OperationNotPermittedException:
        :raises InvalidParameterException:
        :raises MissingRequiredParameterException:
        :raises ServerInternalException:
        :raises ServiceUnavailableException:
        :raises UnknownResourceException:
        :raises InvalidStateTransitionException:
        :raises UnmatchedPolicyPermissionException:
        """
        raise NotImplementedError

    @handler("RejectResourceShareInvitation")
    def reject_resource_share_invitation(
        self,
        context: RequestContext,
        resource_share_invitation_arn: String,
        client_token: String = None,
    ) -> RejectResourceShareInvitationResponse:
        """Rejects an invitation to a resource share from another Amazon Web
        Services account.

        :param resource_share_invitation_arn: Specifies the `Amazon Resource Name
        (ARN) <https://docs.
        :param client_token: Specifies a unique, case-sensitive identifier that you provide to ensure
        the idempotency of the request.
        :returns: RejectResourceShareInvitationResponse
        :raises MalformedArnException:
        :raises OperationNotPermittedException:
        :raises ResourceShareInvitationArnNotFoundException:
        :raises ResourceShareInvitationAlreadyAcceptedException:
        :raises ResourceShareInvitationAlreadyRejectedException:
        :raises ResourceShareInvitationExpiredException:
        :raises ServerInternalException:
        :raises ServiceUnavailableException:
        :raises InvalidClientTokenException:
        :raises IdempotentParameterMismatchException:
        """
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
        """Updates all resource shares that use a managed permission to a different
        managed permission. This operation always applies the default version of
        the target managed permission. You can optionally specify that the
        update applies to only resource shares that currently use a specified
        version. This enables you to update to the latest version, without
        changing the which managed permission is used.

        You can use this operation to update all of your resource shares to use
        the current default version of the permission by specifying the same
        value for the ``fromPermissionArn`` and ``toPermissionArn`` parameters.

        You can use the optional ``fromPermissionVersion`` parameter to update
        only those resources that use a specified version of the managed
        permission to the new managed permission.

        To successfully perform this operation, you must have permission to
        update the resource-based policy on all affected resource types.

        :param from_permission_arn: Specifies the `Amazon Resource Name
        (ARN) <https://docs.
        :param to_permission_arn: Specifies the ARN of the managed permission that you want to associate
        with resource shares in place of the one specified by
        ``fromPerssionArn`` and ``fromPermissionVersion``.
        :param from_permission_version: Specifies that you want to updated the permissions for only those
        resource shares that use the specified version of the managed
        permission.
        :param client_token: Specifies a unique, case-sensitive identifier that you provide to ensure
        the idempotency of the request.
        :returns: ReplacePermissionAssociationsResponse
        :raises MalformedArnException:
        :raises InvalidParameterException:
        :raises ServerInternalException:
        :raises ServiceUnavailableException:
        :raises OperationNotPermittedException:
        :raises UnknownResourceException:
        :raises InvalidClientTokenException:
        :raises IdempotentParameterMismatchException:
        """
        raise NotImplementedError

    @handler("SetDefaultPermissionVersion")
    def set_default_permission_version(
        self,
        context: RequestContext,
        permission_arn: String,
        permission_version: Integer,
        client_token: String = None,
    ) -> SetDefaultPermissionVersionResponse:
        """Designates the specified version number as the default version for the
        specified customer managed permission. New resource shares automatically
        use this new default permission. Existing resource shares continue to
        use their original permission version, but you can use
        ReplacePermissionAssociations to update them.

        :param permission_arn: Specifies the `Amazon Resource Name
        (ARN) <https://docs.
        :param permission_version: Specifies the version number that you want to designate as the default
        for customer managed permission.
        :param client_token: Specifies a unique, case-sensitive identifier that you provide to ensure
        the idempotency of the request.
        :returns: SetDefaultPermissionVersionResponse
        :raises InvalidParameterException:
        :raises MalformedArnException:
        :raises ServerInternalException:
        :raises ServiceUnavailableException:
        :raises UnknownResourceException:
        :raises InvalidClientTokenException:
        :raises IdempotentParameterMismatchException:
        """
        raise NotImplementedError

    @handler("TagResource")
    def tag_resource(
        self,
        context: RequestContext,
        tags: TagList,
        resource_share_arn: String = None,
        resource_arn: String = None,
    ) -> TagResourceResponse:
        """Adds the specified tag keys and values to a resource share or managed
        permission. If you choose a resource share, the tags are attached to
        only the resource share, not to the resources that are in the resource
        share.

        The tags on a managed permission are the same for all versions of the
        managed permission.

        :param tags: A list of one or more tag key and value pairs.
        :param resource_share_arn: Specifies the `Amazon Resource Name
        (ARN) <https://docs.
        :param resource_arn: Specifies the `Amazon Resource Name
        (ARN) <https://docs.
        :returns: TagResourceResponse
        :raises InvalidParameterException:
        :raises MalformedArnException:
        :raises UnknownResourceException:
        :raises TagLimitExceededException:
        :raises ResourceArnNotFoundException:
        :raises TagPolicyViolationException:
        :raises ServerInternalException:
        :raises ServiceUnavailableException:
        """
        raise NotImplementedError

    @handler("UntagResource")
    def untag_resource(
        self,
        context: RequestContext,
        tag_keys: TagKeyList,
        resource_share_arn: String = None,
        resource_arn: String = None,
    ) -> UntagResourceResponse:
        """Removes the specified tag key and value pairs from the specified
        resource share or managed permission.

        :param tag_keys: Specifies a list of one or more tag keys that you want to remove.
        :param resource_share_arn: Specifies the `Amazon Resource Name
        (ARN) <https://docs.
        :param resource_arn: Specifies the `Amazon Resource Name
        (ARN) <https://docs.
        :returns: UntagResourceResponse
        :raises UnknownResourceException:
        :raises InvalidParameterException:
        :raises MalformedArnException:
        :raises ServerInternalException:
        :raises ServiceUnavailableException:
        """
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
        """Modifies some of the properties of the specified resource share.

        :param resource_share_arn: Specifies the `Amazon Resource Name
        (ARN) <https://docs.
        :param name: If specified, the new name that you want to attach to the resource
        share.
        :param allow_external_principals: Specifies whether principals outside your organization in Organizations
        can be associated with a resource share.
        :param client_token: Specifies a unique, case-sensitive identifier that you provide to ensure
        the idempotency of the request.
        :returns: UpdateResourceShareResponse
        :raises IdempotentParameterMismatchException:
        :raises MissingRequiredParameterException:
        :raises UnknownResourceException:
        :raises MalformedArnException:
        :raises InvalidClientTokenException:
        :raises InvalidParameterException:
        :raises OperationNotPermittedException:
        :raises ServerInternalException:
        :raises ServiceUnavailableException:
        """
        raise NotImplementedError
