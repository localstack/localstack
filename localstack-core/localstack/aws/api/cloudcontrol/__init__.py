from datetime import datetime
from enum import StrEnum
from typing import List, Optional, TypedDict

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


class HandlerErrorCode(StrEnum):
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


class Operation(StrEnum):
    CREATE = "CREATE"
    DELETE = "DELETE"
    UPDATE = "UPDATE"


class OperationStatus(StrEnum):
    PENDING = "PENDING"
    IN_PROGRESS = "IN_PROGRESS"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    CANCEL_IN_PROGRESS = "CANCEL_IN_PROGRESS"
    CANCEL_COMPLETE = "CANCEL_COMPLETE"


class AlreadyExistsException(ServiceException):
    code: str = "AlreadyExistsException"
    sender_fault: bool = False
    status_code: int = 400


class ClientTokenConflictException(ServiceException):
    code: str = "ClientTokenConflictException"
    sender_fault: bool = False
    status_code: int = 400


class ConcurrentModificationException(ServiceException):
    code: str = "ConcurrentModificationException"
    sender_fault: bool = False
    status_code: int = 400


class ConcurrentOperationException(ServiceException):
    code: str = "ConcurrentOperationException"
    sender_fault: bool = False
    status_code: int = 400


class GeneralServiceException(ServiceException):
    code: str = "GeneralServiceException"
    sender_fault: bool = False
    status_code: int = 400


class HandlerFailureException(ServiceException):
    code: str = "HandlerFailureException"
    sender_fault: bool = False
    status_code: int = 400


class HandlerInternalFailureException(ServiceException):
    code: str = "HandlerInternalFailureException"
    sender_fault: bool = False
    status_code: int = 400


class InvalidCredentialsException(ServiceException):
    code: str = "InvalidCredentialsException"
    sender_fault: bool = False
    status_code: int = 400


class InvalidRequestException(ServiceException):
    code: str = "InvalidRequestException"
    sender_fault: bool = False
    status_code: int = 400


class NetworkFailureException(ServiceException):
    code: str = "NetworkFailureException"
    sender_fault: bool = False
    status_code: int = 400


class NotStabilizedException(ServiceException):
    code: str = "NotStabilizedException"
    sender_fault: bool = False
    status_code: int = 400


class NotUpdatableException(ServiceException):
    code: str = "NotUpdatableException"
    sender_fault: bool = False
    status_code: int = 400


class PrivateTypeException(ServiceException):
    code: str = "PrivateTypeException"
    sender_fault: bool = False
    status_code: int = 400


class RequestTokenNotFoundException(ServiceException):
    code: str = "RequestTokenNotFoundException"
    sender_fault: bool = False
    status_code: int = 400


class ResourceConflictException(ServiceException):
    code: str = "ResourceConflictException"
    sender_fault: bool = False
    status_code: int = 400


class ResourceNotFoundException(ServiceException):
    code: str = "ResourceNotFoundException"
    sender_fault: bool = False
    status_code: int = 400


class ServiceInternalErrorException(ServiceException):
    code: str = "ServiceInternalErrorException"
    sender_fault: bool = False
    status_code: int = 400


class ServiceLimitExceededException(ServiceException):
    code: str = "ServiceLimitExceededException"
    sender_fault: bool = False
    status_code: int = 400


class ThrottlingException(ServiceException):
    code: str = "ThrottlingException"
    sender_fault: bool = False
    status_code: int = 400


class TypeNotFoundException(ServiceException):
    code: str = "TypeNotFoundException"
    sender_fault: bool = False
    status_code: int = 400


class UnsupportedActionException(ServiceException):
    code: str = "UnsupportedActionException"
    sender_fault: bool = False
    status_code: int = 400


class CancelResourceRequestInput(ServiceRequest):
    RequestToken: RequestToken


Timestamp = datetime


class ProgressEvent(TypedDict, total=False):
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
        self, context: RequestContext, request_token: RequestToken, **kwargs
    ) -> CancelResourceRequestOutput:
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
        **kwargs,
    ) -> CreateResourceOutput:
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
        **kwargs,
    ) -> DeleteResourceOutput:
        raise NotImplementedError

    @handler("GetResource")
    def get_resource(
        self,
        context: RequestContext,
        type_name: TypeName,
        identifier: Identifier,
        type_version_id: TypeVersionId = None,
        role_arn: RoleArn = None,
        **kwargs,
    ) -> GetResourceOutput:
        raise NotImplementedError

    @handler("GetResourceRequestStatus")
    def get_resource_request_status(
        self, context: RequestContext, request_token: RequestToken, **kwargs
    ) -> GetResourceRequestStatusOutput:
        raise NotImplementedError

    @handler("ListResourceRequests")
    def list_resource_requests(
        self,
        context: RequestContext,
        max_results: MaxResults = None,
        next_token: NextToken = None,
        resource_request_status_filter: ResourceRequestStatusFilter = None,
        **kwargs,
    ) -> ListResourceRequestsOutput:
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
        **kwargs,
    ) -> ListResourcesOutput:
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
        **kwargs,
    ) -> UpdateResourceOutput:
        raise NotImplementedError
