import sys
from datetime import datetime
from typing import List, Optional

if sys.version_info >= (3, 8):
    from typing import TypedDict
else:
    from typing_extensions import TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

ClientToken = str
ErrorMessage = str
HandlerNextToken = str
Identifier = str
MaxResults = int
NextToken = str
PatchDocument = str
Properties = str
RequestToken = str
RoleArn = str
StatusMessage = str
TypeName = str
TypeVersionId = str


class HandlerErrorCode(str):
    NotUpdatable = "NotUpdatable"
    InvalidRequest = "InvalidRequest"
    AccessDenied = "AccessDenied"
    InvalidCredentials = "InvalidCredentials"
    AlreadyExists = "AlreadyExists"
    NotFound = "NotFound"
    ResourceConflict = "ResourceConflict"
    Throttling = "Throttling"
    ServiceLimitExceeded = "ServiceLimitExceeded"
    NotStabilized = "NotStabilized"
    GeneralServiceException = "GeneralServiceException"
    ServiceInternalError = "ServiceInternalError"
    ServiceTimeout = "ServiceTimeout"
    NetworkFailure = "NetworkFailure"
    InternalFailure = "InternalFailure"


class Operation(str):
    CREATE = "CREATE"
    DELETE = "DELETE"
    UPDATE = "UPDATE"


class OperationStatus(str):
    PENDING = "PENDING"
    IN_PROGRESS = "IN_PROGRESS"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    CANCEL_IN_PROGRESS = "CANCEL_IN_PROGRESS"
    CANCEL_COMPLETE = "CANCEL_COMPLETE"


class AlreadyExistsException(ServiceException):
    """The resource with the name requested already exists."""

    code: str = "AlreadyExistsException"
    sender_fault: bool = False
    status_code: int = 400


class ClientTokenConflictException(ServiceException):
    """The specified client token has already been used in another resource
    request.

    It's best practice for client tokens to be unique for each resource
    operation request. However, client token expire after 36 hours.
    """

    code: str = "ClientTokenConflictException"
    sender_fault: bool = False
    status_code: int = 400


class ConcurrentModificationException(ServiceException):
    """The resource is currently being modified by another operation."""

    code: str = "ConcurrentModificationException"
    sender_fault: bool = False
    status_code: int = 400


class ConcurrentOperationException(ServiceException):
    """Another resource operation is currently being performed on this
    resource.
    """

    code: str = "ConcurrentOperationException"
    sender_fault: bool = False
    status_code: int = 400


class GeneralServiceException(ServiceException):
    """The resource handler has returned that the downstream service generated
    an error that doesn't map to any other handler error code.
    """

    code: str = "GeneralServiceException"
    sender_fault: bool = False
    status_code: int = 400


class HandlerFailureException(ServiceException):
    """The resource handler has failed without a returning a more specific
    error code. This can include timeouts.
    """

    code: str = "HandlerFailureException"
    sender_fault: bool = False
    status_code: int = 400


class HandlerInternalFailureException(ServiceException):
    """The resource handler has returned that an unexpected error occurred
    within the resource handler.
    """

    code: str = "HandlerInternalFailureException"
    sender_fault: bool = False
    status_code: int = 400


class InvalidCredentialsException(ServiceException):
    """The resource handler has returned that the credentials provided by the
    user are invalid.
    """

    code: str = "InvalidCredentialsException"
    sender_fault: bool = False
    status_code: int = 400


class InvalidRequestException(ServiceException):
    """The resource handler has returned that invalid input from the user has
    generated a generic exception.
    """

    code: str = "InvalidRequestException"
    sender_fault: bool = False
    status_code: int = 400


class NetworkFailureException(ServiceException):
    """The resource handler has returned that the request couldn't be completed
    due to networking issues, such as a failure to receive a response from
    the server.
    """

    code: str = "NetworkFailureException"
    sender_fault: bool = False
    status_code: int = 400


class NotStabilizedException(ServiceException):
    """The resource handler has returned that the downstream resource failed to
    complete all of its ready-state checks.
    """

    code: str = "NotStabilizedException"
    sender_fault: bool = False
    status_code: int = 400


class NotUpdatableException(ServiceException):
    """One or more properties included in this resource operation are defined
    as create-only, and therefore can't be updated.
    """

    code: str = "NotUpdatableException"
    sender_fault: bool = False
    status_code: int = 400


class PrivateTypeException(ServiceException):
    """Cloud Control API hasn't received a valid response from the resource
    handler, due to a configuration error. This includes issues such as the
    resource handler returning an invalid response, or timing out.
    """

    code: str = "PrivateTypeException"
    sender_fault: bool = False
    status_code: int = 400


class RequestTokenNotFoundException(ServiceException):
    """A resource operation with the specified request token can't be found."""

    code: str = "RequestTokenNotFoundException"
    sender_fault: bool = False
    status_code: int = 400


class ResourceConflictException(ServiceException):
    """The resource is temporarily unavailable to be acted upon. For example,
    if the resource is currently undergoing an operation and can't be acted
    upon until that operation is finished.
    """

    code: str = "ResourceConflictException"
    sender_fault: bool = False
    status_code: int = 400


class ResourceNotFoundException(ServiceException):
    """A resource with the specified identifier can't be found."""

    code: str = "ResourceNotFoundException"
    sender_fault: bool = False
    status_code: int = 400


class ServiceInternalErrorException(ServiceException):
    """The resource handler has returned that the downstream service returned
    an internal error, typically with a ``5XX HTTP`` status code.
    """

    code: str = "ServiceInternalErrorException"
    sender_fault: bool = False
    status_code: int = 400


class ServiceLimitExceededException(ServiceException):
    """The resource handler has returned that a non-transient resource limit
    was reached on the service side.
    """

    code: str = "ServiceLimitExceededException"
    sender_fault: bool = False
    status_code: int = 400


class ThrottlingException(ServiceException):
    """The request was denied due to request throttling."""

    code: str = "ThrottlingException"
    sender_fault: bool = False
    status_code: int = 400


class TypeNotFoundException(ServiceException):
    """The specified extension doesn't exist in the CloudFormation registry."""

    code: str = "TypeNotFoundException"
    sender_fault: bool = False
    status_code: int = 400


class UnsupportedActionException(ServiceException):
    """The specified resource doesn't support this resource operation."""

    code: str = "UnsupportedActionException"
    sender_fault: bool = False
    status_code: int = 400


class CancelResourceRequestInput(ServiceRequest):
    RequestToken: RequestToken


Timestamp = datetime


class ProgressEvent(TypedDict, total=False):
    """Represents the current status of a resource operation request. For more
    information, see `Managing resource operation
    requests <https://docs.aws.amazon.com/cloudcontrolapi/latest/userguide/resource-operations-manage-requests.html>`__
    in the *Amazon Web Services Cloud Control API User Guide*.
    """

    TypeName: Optional[TypeName]
    Identifier: Optional[Identifier]
    RequestToken: Optional[RequestToken]
    Operation: Optional[Operation]
    OperationStatus: Optional[OperationStatus]
    EventTime: Optional[Timestamp]
    ResourceModel: Optional[Properties]
    StatusMessage: Optional[StatusMessage]
    ErrorCode: Optional[HandlerErrorCode]
    RetryAfter: Optional[Timestamp]


class CancelResourceRequestOutput(TypedDict, total=False):
    ProgressEvent: Optional[ProgressEvent]


class CreateResourceInput(ServiceRequest):
    TypeName: TypeName
    TypeVersionId: Optional[TypeVersionId]
    RoleArn: Optional[RoleArn]
    ClientToken: Optional[ClientToken]
    DesiredState: Properties


class CreateResourceOutput(TypedDict, total=False):
    ProgressEvent: Optional[ProgressEvent]


class DeleteResourceInput(ServiceRequest):
    TypeName: TypeName
    TypeVersionId: Optional[TypeVersionId]
    RoleArn: Optional[RoleArn]
    ClientToken: Optional[ClientToken]
    Identifier: Identifier


class DeleteResourceOutput(TypedDict, total=False):
    ProgressEvent: Optional[ProgressEvent]


class GetResourceInput(ServiceRequest):
    TypeName: TypeName
    TypeVersionId: Optional[TypeVersionId]
    RoleArn: Optional[RoleArn]
    Identifier: Identifier


class ResourceDescription(TypedDict, total=False):
    """Represents information about a provisioned resource."""

    Identifier: Optional[Identifier]
    Properties: Optional[Properties]


class GetResourceOutput(TypedDict, total=False):
    TypeName: Optional[TypeName]
    ResourceDescription: Optional[ResourceDescription]


class GetResourceRequestStatusInput(ServiceRequest):
    RequestToken: RequestToken


class GetResourceRequestStatusOutput(TypedDict, total=False):
    ProgressEvent: Optional[ProgressEvent]


OperationStatuses = List[OperationStatus]
Operations = List[Operation]


class ResourceRequestStatusFilter(TypedDict, total=False):
    """The filter criteria to use in determining the requests returned."""

    Operations: Optional[Operations]
    OperationStatuses: Optional[OperationStatuses]


class ListResourceRequestsInput(ServiceRequest):
    MaxResults: Optional[MaxResults]
    NextToken: Optional[NextToken]
    ResourceRequestStatusFilter: Optional[ResourceRequestStatusFilter]


ResourceRequestStatusSummaries = List[ProgressEvent]


class ListResourceRequestsOutput(TypedDict, total=False):
    ResourceRequestStatusSummaries: Optional[ResourceRequestStatusSummaries]
    NextToken: Optional[NextToken]


class ListResourcesInput(ServiceRequest):
    TypeName: TypeName
    TypeVersionId: Optional[TypeVersionId]
    RoleArn: Optional[RoleArn]
    NextToken: Optional[HandlerNextToken]
    MaxResults: Optional[MaxResults]
    ResourceModel: Optional[Properties]


ResourceDescriptions = List[ResourceDescription]


class ListResourcesOutput(TypedDict, total=False):
    TypeName: Optional[TypeName]
    ResourceDescriptions: Optional[ResourceDescriptions]
    NextToken: Optional[HandlerNextToken]


class UpdateResourceInput(ServiceRequest):
    TypeName: TypeName
    TypeVersionId: Optional[TypeVersionId]
    RoleArn: Optional[RoleArn]
    ClientToken: Optional[ClientToken]
    Identifier: Identifier
    PatchDocument: PatchDocument


class UpdateResourceOutput(TypedDict, total=False):
    ProgressEvent: Optional[ProgressEvent]


class CloudcontrolApi:

    service = "cloudcontrol"
    version = "2021-09-30"

    @handler("CancelResourceRequest")
    def cancel_resource_request(
        self, context: RequestContext, request_token: RequestToken
    ) -> CancelResourceRequestOutput:
        """Cancels the specified resource operation request. For more information,
        see `Canceling resource operation
        requests <https://docs.aws.amazon.com/cloudcontrolapi/latest/userguide/resource-operations-manage-requests.html#resource-operations-manage-requests-cancel>`__
        in the *Amazon Web Services Cloud Control API User Guide*.

        Only resource operations requests with a status of ``PENDING`` or
        ``IN_PROGRESS`` can be canceled.

        :param request_token: The ``RequestToken`` of the ``ProgressEvent`` object returned by the
        resource operation request.
        :returns: CancelResourceRequestOutput
        :raises ConcurrentModificationException:
        :raises RequestTokenNotFoundException:
        """
        raise NotImplementedError

    @handler("CreateResource")
    def create_resource(
        self,
        context: RequestContext,
        type_name: TypeName,
        desired_state: Properties,
        type_version_id: TypeVersionId = None,
        role_arn: RoleArn = None,
        client_token: ClientToken = None,
    ) -> CreateResourceOutput:
        """Creates the specified resource. For more information, see `Creating a
        resource <https://docs.aws.amazon.com/cloudcontrolapi/latest/userguide/resource-operations-create.html>`__
        in the *Amazon Web Services Cloud Control API User Guide*.

        After you have initiated a resource creation request, you can monitor
        the progress of your request by calling
        `GetResourceRequestStatus <https://docs.aws.amazon.com/cloudcontrolapi/latest/APIReference/API_GetResourceRequestStatus.html>`__
        using the ``RequestToken`` of the ``ProgressEvent`` type returned by
        ``CreateResource``.

        :param type_name: The name of the resource type.
        :param desired_state: Structured data format representing the desired state of the resource,
        consisting of that resource's properties and their desired values.
        :param type_version_id: For private resource types, the type version to use in this resource
        operation.
        :param role_arn: The Amazon Resource Name (ARN) of the Identity and Access Management
        (IAM) role for Cloud Control API to use when performing this resource
        operation.
        :param client_token: A unique identifier to ensure the idempotency of the resource request.
        :returns: CreateResourceOutput
        :raises AlreadyExistsException:
        :raises HandlerInternalFailureException:
        :raises GeneralServiceException:
        :raises NotUpdatableException:
        :raises TypeNotFoundException:
        :raises ConcurrentOperationException:
        :raises InvalidRequestException:
        :raises PrivateTypeException:
        :raises ResourceNotFoundException:
        :raises NetworkFailureException:
        :raises UnsupportedActionException:
        :raises NotStabilizedException:
        :raises ServiceInternalErrorException:
        :raises HandlerFailureException:
        :raises ServiceLimitExceededException:
        :raises InvalidCredentialsException:
        :raises ResourceConflictException:
        :raises ClientTokenConflictException:
        :raises ThrottlingException:
        """
        raise NotImplementedError

    @handler("DeleteResource")
    def delete_resource(
        self,
        context: RequestContext,
        type_name: TypeName,
        identifier: Identifier,
        type_version_id: TypeVersionId = None,
        role_arn: RoleArn = None,
        client_token: ClientToken = None,
    ) -> DeleteResourceOutput:
        """Deletes the specified resource. For details, see `Deleting a
        resource <https://docs.aws.amazon.com/cloudcontrolapi/latest/userguide/resource-operations-delete.html>`__
        in the *Amazon Web Services Cloud Control API User Guide*.

        After you have initiated a resource deletion request, you can monitor
        the progress of your request by calling
        `GetResourceRequestStatus <https://docs.aws.amazon.com/cloudcontrolapi/latest/APIReference/API_GetResourceRequestStatus.html>`__
        using the ``RequestToken`` of the ``ProgressEvent`` returned by
        ``DeleteResource``.

        :param type_name: The name of the resource type.
        :param identifier: The identifier for the resource.
        :param type_version_id: For private resource types, the type version to use in this resource
        operation.
        :param role_arn: The Amazon Resource Name (ARN) of the Identity and Access Management
        (IAM) role for Cloud Control API to use when performing this resource
        operation.
        :param client_token: A unique identifier to ensure the idempotency of the resource request.
        :returns: DeleteResourceOutput
        :raises AlreadyExistsException:
        :raises HandlerInternalFailureException:
        :raises GeneralServiceException:
        :raises NotUpdatableException:
        :raises TypeNotFoundException:
        :raises ConcurrentOperationException:
        :raises InvalidRequestException:
        :raises PrivateTypeException:
        :raises ResourceNotFoundException:
        :raises NetworkFailureException:
        :raises UnsupportedActionException:
        :raises NotStabilizedException:
        :raises ServiceInternalErrorException:
        :raises HandlerFailureException:
        :raises ServiceLimitExceededException:
        :raises InvalidCredentialsException:
        :raises ResourceConflictException:
        :raises ClientTokenConflictException:
        :raises ThrottlingException:
        """
        raise NotImplementedError

    @handler("GetResource")
    def get_resource(
        self,
        context: RequestContext,
        type_name: TypeName,
        identifier: Identifier,
        type_version_id: TypeVersionId = None,
        role_arn: RoleArn = None,
    ) -> GetResourceOutput:
        """Returns information about the current state of the specified resource.
        For details, see `Reading a resource's current
        state <https://docs.aws.amazon.com/cloudcontrolapi/latest/userguide/resource-operations-read.html>`__.

        You can use this action to return information about an existing resource
        in your account and Amazon Web Services Region, whether those resources
        were provisioned using Cloud Control API.

        :param type_name: The name of the resource type.
        :param identifier: The identifier for the resource.
        :param type_version_id: For private resource types, the type version to use in this resource
        operation.
        :param role_arn: The Amazon Resource Name (ARN) of the Identity and Access Management
        (IAM) role for Cloud Control API to use when performing this resource
        operation.
        :returns: GetResourceOutput
        :raises AlreadyExistsException:
        :raises HandlerInternalFailureException:
        :raises GeneralServiceException:
        :raises NotUpdatableException:
        :raises TypeNotFoundException:
        :raises InvalidRequestException:
        :raises PrivateTypeException:
        :raises ResourceNotFoundException:
        :raises NetworkFailureException:
        :raises UnsupportedActionException:
        :raises NotStabilizedException:
        :raises ServiceInternalErrorException:
        :raises HandlerFailureException:
        :raises ServiceLimitExceededException:
        :raises InvalidCredentialsException:
        :raises ResourceConflictException:
        :raises ThrottlingException:
        """
        raise NotImplementedError

    @handler("GetResourceRequestStatus")
    def get_resource_request_status(
        self, context: RequestContext, request_token: RequestToken
    ) -> GetResourceRequestStatusOutput:
        """Returns the current status of a resource operation request. For more
        information, see `Tracking the progress of resource operation
        requests <https://docs.aws.amazon.com/cloudcontrolapi/latest/userguide/resource-operations-manage-requests.html#resource-operations-manage-requests-track>`__
        in the *Amazon Web Services Cloud Control API User Guide*.

        :param request_token: A unique token used to track the progress of the resource operation
        request.
        :returns: GetResourceRequestStatusOutput
        :raises RequestTokenNotFoundException:
        """
        raise NotImplementedError

    @handler("ListResourceRequests")
    def list_resource_requests(
        self,
        context: RequestContext,
        max_results: MaxResults = None,
        next_token: NextToken = None,
        resource_request_status_filter: ResourceRequestStatusFilter = None,
    ) -> ListResourceRequestsOutput:
        """Returns existing resource operation requests. This includes requests of
        all status types. For more information, see `Listing active resource
        operation
        requests <https://docs.aws.amazon.com/cloudcontrolapi/latest/userguide/resource-operations-manage-requests.html#resource-operations-manage-requests-list>`__
        in the *Amazon Web Services Cloud Control API User Guide*.

        Resource operation requests expire after 7 days.

        :param max_results: The maximum number of results to be returned with a single call.
        :param next_token: If the previous paginated request didn't return all of the remaining
        results, the response object's ``NextToken`` parameter value is set to a
        token.
        :param resource_request_status_filter: The filter criteria to apply to the requests returned.
        :returns: ListResourceRequestsOutput
        """
        raise NotImplementedError

    @handler("ListResources")
    def list_resources(
        self,
        context: RequestContext,
        type_name: TypeName,
        type_version_id: TypeVersionId = None,
        role_arn: RoleArn = None,
        next_token: HandlerNextToken = None,
        max_results: MaxResults = None,
        resource_model: Properties = None,
    ) -> ListResourcesOutput:
        """Returns information about the specified resources. For more information,
        see `Discovering
        resources <https://docs.aws.amazon.com/cloudcontrolapi/latest/userguide/resource-operations-list.html>`__
        in the *Amazon Web Services Cloud Control API User Guide*.

        You can use this action to return information about existing resources
        in your account and Amazon Web Services Region, whether those resources
        were provisioned using Cloud Control API.

        :param type_name: The name of the resource type.
        :param type_version_id: For private resource types, the type version to use in this resource
        operation.
        :param role_arn: The Amazon Resource Name (ARN) of the Identity and Access Management
        (IAM) role for Cloud Control API to use when performing this resource
        operation.
        :param next_token: If the previous paginated request didn't return all of the remaining
        results, the response object's ``NextToken`` parameter value is set to a
        token.
        :param max_results: Reserved.
        :param resource_model: The resource model to use to select the resources to return.
        :returns: ListResourcesOutput
        :raises AlreadyExistsException:
        :raises HandlerInternalFailureException:
        :raises GeneralServiceException:
        :raises NotUpdatableException:
        :raises TypeNotFoundException:
        :raises InvalidRequestException:
        :raises PrivateTypeException:
        :raises ResourceNotFoundException:
        :raises NetworkFailureException:
        :raises UnsupportedActionException:
        :raises NotStabilizedException:
        :raises ServiceInternalErrorException:
        :raises HandlerFailureException:
        :raises ServiceLimitExceededException:
        :raises InvalidCredentialsException:
        :raises ResourceConflictException:
        :raises ThrottlingException:
        """
        raise NotImplementedError

    @handler("UpdateResource")
    def update_resource(
        self,
        context: RequestContext,
        type_name: TypeName,
        identifier: Identifier,
        patch_document: PatchDocument,
        type_version_id: TypeVersionId = None,
        role_arn: RoleArn = None,
        client_token: ClientToken = None,
    ) -> UpdateResourceOutput:
        """Updates the specified property values in the resource.

        You specify your resource property updates as a list of patch operations
        contained in a JSON patch document that adheres to the `RFC 6902 -
        JavaScript Object Notation (JSON)
        Patch <https://datatracker.ietf.org/doc/html/rfc6902>`__ standard.

        For details on how Cloud Control API performs resource update
        operations, see `Updating a
        resource <https://docs.aws.amazon.com/cloudcontrolapi/latest/userguide/resource-operations-update.html>`__
        in the *Amazon Web Services Cloud Control API User Guide*.

        After you have initiated a resource update request, you can monitor the
        progress of your request by calling
        `GetResourceRequestStatus <https://docs.aws.amazon.com/cloudcontrolapi/latest/APIReference/API_GetResourceRequestStatus.html>`__
        using the ``RequestToken`` of the ``ProgressEvent`` returned by
        ``UpdateResource``.

        For more information about the properties of a specific resource, refer
        to the related topic for the resource in the `Resource and property
        types
        reference <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-template-resource-type-ref.html>`__
        in the *CloudFormation Users Guide*.

        :param type_name: The name of the resource type.
        :param identifier: The identifier for the resource.
        :param patch_document: A JavaScript Object Notation (JSON) document listing the patch
        operations that represent the updates to apply to the current resource
        properties.
        :param type_version_id: For private resource types, the type version to use in this resource
        operation.
        :param role_arn: The Amazon Resource Name (ARN) of the Identity and Access Management
        (IAM) role for Cloud Control API to use when performing this resource
        operation.
        :param client_token: A unique identifier to ensure the idempotency of the resource request.
        :returns: UpdateResourceOutput
        :raises AlreadyExistsException:
        :raises HandlerInternalFailureException:
        :raises GeneralServiceException:
        :raises NotUpdatableException:
        :raises TypeNotFoundException:
        :raises ConcurrentOperationException:
        :raises InvalidRequestException:
        :raises PrivateTypeException:
        :raises ResourceNotFoundException:
        :raises NetworkFailureException:
        :raises UnsupportedActionException:
        :raises NotStabilizedException:
        :raises ServiceInternalErrorException:
        :raises HandlerFailureException:
        :raises ServiceLimitExceededException:
        :raises InvalidCredentialsException:
        :raises ResourceConflictException:
        :raises ClientTokenConflictException:
        :raises ThrottlingException:
        """
        raise NotImplementedError
