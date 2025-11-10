from datetime import datetime
from enum import StrEnum
from typing import TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

ClientToken = str
ErrorMessage = str
HandlerNextToken = str
HookFailureMode = str
HookInvocationPoint = str
HookStatus = str
HookTypeArn = str
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
    UnauthorizedTaggingOperation = "UnauthorizedTaggingOperation"
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
    TypeName: TypeName | None
    Identifier: Identifier | None
    RequestToken: RequestToken | None
    HooksRequestToken: RequestToken | None
    Operation: Operation | None
    OperationStatus: OperationStatus | None
    EventTime: Timestamp | None
    ResourceModel: Properties | None
    StatusMessage: StatusMessage | None
    ErrorCode: HandlerErrorCode | None
    RetryAfter: Timestamp | None


class CancelResourceRequestOutput(TypedDict, total=False):
    ProgressEvent: ProgressEvent | None


class CreateResourceInput(ServiceRequest):
    TypeName: TypeName
    TypeVersionId: TypeVersionId | None
    RoleArn: RoleArn | None
    ClientToken: ClientToken | None
    DesiredState: Properties


class CreateResourceOutput(TypedDict, total=False):
    ProgressEvent: ProgressEvent | None


class DeleteResourceInput(ServiceRequest):
    TypeName: TypeName
    TypeVersionId: TypeVersionId | None
    RoleArn: RoleArn | None
    ClientToken: ClientToken | None
    Identifier: Identifier


class DeleteResourceOutput(TypedDict, total=False):
    ProgressEvent: ProgressEvent | None


class GetResourceInput(ServiceRequest):
    TypeName: TypeName
    TypeVersionId: TypeVersionId | None
    RoleArn: RoleArn | None
    Identifier: Identifier


class ResourceDescription(TypedDict, total=False):
    Identifier: Identifier | None
    Properties: Properties | None


class GetResourceOutput(TypedDict, total=False):
    TypeName: TypeName | None
    ResourceDescription: ResourceDescription | None


class GetResourceRequestStatusInput(ServiceRequest):
    RequestToken: RequestToken


class HookProgressEvent(TypedDict, total=False):
    HookTypeName: TypeName | None
    HookTypeVersionId: TypeVersionId | None
    HookTypeArn: HookTypeArn | None
    InvocationPoint: HookInvocationPoint | None
    HookStatus: HookStatus | None
    HookEventTime: Timestamp | None
    HookStatusMessage: StatusMessage | None
    FailureMode: HookFailureMode | None


HooksProgressEvent = list[HookProgressEvent]


class GetResourceRequestStatusOutput(TypedDict, total=False):
    ProgressEvent: ProgressEvent | None
    HooksProgressEvent: HooksProgressEvent | None


OperationStatuses = list[OperationStatus]
Operations = list[Operation]


class ResourceRequestStatusFilter(TypedDict, total=False):
    Operations: Operations | None
    OperationStatuses: OperationStatuses | None


class ListResourceRequestsInput(ServiceRequest):
    MaxResults: MaxResults | None
    NextToken: NextToken | None
    ResourceRequestStatusFilter: ResourceRequestStatusFilter | None


ResourceRequestStatusSummaries = list[ProgressEvent]


class ListResourceRequestsOutput(TypedDict, total=False):
    ResourceRequestStatusSummaries: ResourceRequestStatusSummaries | None
    NextToken: NextToken | None


class ListResourcesInput(ServiceRequest):
    TypeName: TypeName
    TypeVersionId: TypeVersionId | None
    RoleArn: RoleArn | None
    NextToken: HandlerNextToken | None
    MaxResults: MaxResults | None
    ResourceModel: Properties | None


ResourceDescriptions = list[ResourceDescription]


class ListResourcesOutput(TypedDict, total=False):
    TypeName: TypeName | None
    ResourceDescriptions: ResourceDescriptions | None
    NextToken: HandlerNextToken | None


class UpdateResourceInput(ServiceRequest):
    TypeName: TypeName
    TypeVersionId: TypeVersionId | None
    RoleArn: RoleArn | None
    ClientToken: ClientToken | None
    Identifier: Identifier
    PatchDocument: PatchDocument


class UpdateResourceOutput(TypedDict, total=False):
    ProgressEvent: ProgressEvent | None


class CloudcontrolApi:
    service: str = "cloudcontrol"
    version: str = "2021-09-30"

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
        type_version_id: TypeVersionId | None = None,
        role_arn: RoleArn | None = None,
        client_token: ClientToken | None = None,
        **kwargs,
    ) -> CreateResourceOutput:
        raise NotImplementedError

    @handler("DeleteResource")
    def delete_resource(
        self,
        context: RequestContext,
        type_name: TypeName,
        identifier: Identifier,
        type_version_id: TypeVersionId | None = None,
        role_arn: RoleArn | None = None,
        client_token: ClientToken | None = None,
        **kwargs,
    ) -> DeleteResourceOutput:
        raise NotImplementedError

    @handler("GetResource")
    def get_resource(
        self,
        context: RequestContext,
        type_name: TypeName,
        identifier: Identifier,
        type_version_id: TypeVersionId | None = None,
        role_arn: RoleArn | None = None,
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
        max_results: MaxResults | None = None,
        next_token: NextToken | None = None,
        resource_request_status_filter: ResourceRequestStatusFilter | None = None,
        **kwargs,
    ) -> ListResourceRequestsOutput:
        raise NotImplementedError

    @handler("ListResources")
    def list_resources(
        self,
        context: RequestContext,
        type_name: TypeName,
        type_version_id: TypeVersionId | None = None,
        role_arn: RoleArn | None = None,
        next_token: HandlerNextToken | None = None,
        max_results: MaxResults | None = None,
        resource_model: Properties | None = None,
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
        type_version_id: TypeVersionId | None = None,
        role_arn: RoleArn | None = None,
        client_token: ClientToken | None = None,
        **kwargs,
    ) -> UpdateResourceOutput:
        raise NotImplementedError
