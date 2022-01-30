import sys
from datetime import datetime
from typing import List, Optional

if sys.version_info >= (3, 8):
    from typing import TypedDict
else:
    from typing_extensions import TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

AddressAllocationId = str
Arn = str
CallbackToken = str
Certificate = str
CustomStepTarget = str
CustomStepTimeoutSeconds = int
DirectoryId = str
EfsFileSystemId = str
EfsPath = str
ExecutionErrorMessage = str
ExecutionId = str
ExternalId = str
Fips = bool
Function = str
HomeDirectory = str
HostKey = str
HostKeyFingerprint = str
LogGroupName = str
MapEntry = str
MapTarget = str
MaxResults = int
Message = str
NextToken = str
NullableRole = str
PassiveIp = str
Policy = str
PostAuthenticationLoginBanner = str
PreAuthenticationLoginBanner = str
Resource = str
ResourceType = str
Response = str
RetryAfterSeconds = str
Role = str
S3Bucket = str
S3Etag = str
S3Key = str
S3TagKey = str
S3TagValue = str
S3VersionId = str
SecurityGroupId = str
SecurityPolicyName = str
SecurityPolicyOption = str
ServerId = str
ServiceErrorMessage = str
SessionId = str
SourceFileLocation = str
SourceIp = str
SshPublicKeyBody = str
SshPublicKeyCount = int
SshPublicKeyId = str
StatusCode = int
StepResultOutputsJson = str
SubnetId = str
TagKey = str
TagValue = str
Url = str
UserCount = int
UserName = str
UserPassword = str
VpcEndpointId = str
VpcId = str
WorkflowDescription = str
WorkflowId = str
WorkflowStepName = str


class CustomStepStatus(str):
    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"


class Domain(str):
    S3 = "S3"
    EFS = "EFS"


class EndpointType(str):
    PUBLIC = "PUBLIC"
    VPC = "VPC"
    VPC_ENDPOINT = "VPC_ENDPOINT"


class ExecutionErrorType(str):
    PERMISSION_DENIED = "PERMISSION_DENIED"


class ExecutionStatus(str):
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    EXCEPTION = "EXCEPTION"
    HANDLING_EXCEPTION = "HANDLING_EXCEPTION"


class HomeDirectoryType(str):
    PATH = "PATH"
    LOGICAL = "LOGICAL"


class IdentityProviderType(str):
    SERVICE_MANAGED = "SERVICE_MANAGED"
    API_GATEWAY = "API_GATEWAY"
    AWS_DIRECTORY_SERVICE = "AWS_DIRECTORY_SERVICE"
    AWS_LAMBDA = "AWS_LAMBDA"


class OverwriteExisting(str):
    TRUE = "TRUE"
    FALSE = "FALSE"


class Protocol(str):
    SFTP = "SFTP"
    FTP = "FTP"
    FTPS = "FTPS"


class State(str):
    OFFLINE = "OFFLINE"
    ONLINE = "ONLINE"
    STARTING = "STARTING"
    STOPPING = "STOPPING"
    START_FAILED = "START_FAILED"
    STOP_FAILED = "STOP_FAILED"


class TlsSessionResumptionMode(str):
    DISABLED = "DISABLED"
    ENABLED = "ENABLED"
    ENFORCED = "ENFORCED"


class WorkflowStepType(str):
    COPY = "COPY"
    CUSTOM = "CUSTOM"
    TAG = "TAG"
    DELETE = "DELETE"


class AccessDeniedException(ServiceException):
    Message: Optional[ServiceErrorMessage]


class ConflictException(ServiceException):
    Message: Message


class InternalServiceError(ServiceException):
    Message: Message


class InvalidNextTokenException(ServiceException):
    Message: Message


class InvalidRequestException(ServiceException):
    Message: Message


class ResourceExistsException(ServiceException):
    Message: Message
    Resource: Resource
    ResourceType: ResourceType


class ResourceNotFoundException(ServiceException):
    Message: Message
    Resource: Resource
    ResourceType: ResourceType


class ServiceUnavailableException(ServiceException):
    Message: Optional[ServiceErrorMessage]


class ThrottlingException(ServiceException):
    RetryAfterSeconds: Optional[RetryAfterSeconds]


AddressAllocationIds = List[AddressAllocationId]


class EfsFileLocation(TypedDict, total=False):
    FileSystemId: Optional[EfsFileSystemId]
    Path: Optional[EfsPath]


class S3InputFileLocation(TypedDict, total=False):
    Bucket: Optional[S3Bucket]
    Key: Optional[S3Key]


class InputFileLocation(TypedDict, total=False):
    S3FileLocation: Optional[S3InputFileLocation]
    EfsFileLocation: Optional[EfsFileLocation]


class CopyStepDetails(TypedDict, total=False):
    Name: Optional[WorkflowStepName]
    DestinationFileLocation: Optional[InputFileLocation]
    OverwriteExisting: Optional[OverwriteExisting]
    SourceFileLocation: Optional[SourceFileLocation]


PosixId = int
SecondaryGids = List[PosixId]


class PosixProfile(TypedDict, total=False):
    Uid: PosixId
    Gid: PosixId
    SecondaryGids: Optional[SecondaryGids]


class HomeDirectoryMapEntry(TypedDict, total=False):
    Entry: MapEntry
    Target: MapTarget


HomeDirectoryMappings = List[HomeDirectoryMapEntry]


class CreateAccessRequest(ServiceRequest):
    HomeDirectory: Optional[HomeDirectory]
    HomeDirectoryType: Optional[HomeDirectoryType]
    HomeDirectoryMappings: Optional[HomeDirectoryMappings]
    Policy: Optional[Policy]
    PosixProfile: Optional[PosixProfile]
    Role: Role
    ServerId: ServerId
    ExternalId: ExternalId


class CreateAccessResponse(TypedDict, total=False):
    ServerId: ServerId
    ExternalId: ExternalId


class WorkflowDetail(TypedDict, total=False):
    WorkflowId: WorkflowId
    ExecutionRole: Role


OnUploadWorkflowDetails = List[WorkflowDetail]


class WorkflowDetails(TypedDict, total=False):
    OnUpload: OnUploadWorkflowDetails


class Tag(TypedDict, total=False):
    Key: TagKey
    Value: TagValue


Tags = List[Tag]


class ProtocolDetails(TypedDict, total=False):
    PassiveIp: Optional[PassiveIp]
    TlsSessionResumptionMode: Optional[TlsSessionResumptionMode]


Protocols = List[Protocol]


class IdentityProviderDetails(TypedDict, total=False):
    Url: Optional[Url]
    InvocationRole: Optional[Role]
    DirectoryId: Optional[DirectoryId]
    Function: Optional[Function]


SecurityGroupIds = List[SecurityGroupId]
SubnetIds = List[SubnetId]


class EndpointDetails(TypedDict, total=False):
    AddressAllocationIds: Optional[AddressAllocationIds]
    SubnetIds: Optional[SubnetIds]
    VpcEndpointId: Optional[VpcEndpointId]
    VpcId: Optional[VpcId]
    SecurityGroupIds: Optional[SecurityGroupIds]


class CreateServerRequest(ServiceRequest):
    Certificate: Optional[Certificate]
    Domain: Optional[Domain]
    EndpointDetails: Optional[EndpointDetails]
    EndpointType: Optional[EndpointType]
    HostKey: Optional[HostKey]
    IdentityProviderDetails: Optional[IdentityProviderDetails]
    IdentityProviderType: Optional[IdentityProviderType]
    LoggingRole: Optional[Role]
    PostAuthenticationLoginBanner: Optional[PostAuthenticationLoginBanner]
    PreAuthenticationLoginBanner: Optional[PreAuthenticationLoginBanner]
    Protocols: Optional[Protocols]
    ProtocolDetails: Optional[ProtocolDetails]
    SecurityPolicyName: Optional[SecurityPolicyName]
    Tags: Optional[Tags]
    WorkflowDetails: Optional[WorkflowDetails]


class CreateServerResponse(TypedDict, total=False):
    ServerId: ServerId


class CreateUserRequest(ServiceRequest):
    HomeDirectory: Optional[HomeDirectory]
    HomeDirectoryType: Optional[HomeDirectoryType]
    HomeDirectoryMappings: Optional[HomeDirectoryMappings]
    Policy: Optional[Policy]
    PosixProfile: Optional[PosixProfile]
    Role: Role
    ServerId: ServerId
    SshPublicKeyBody: Optional[SshPublicKeyBody]
    Tags: Optional[Tags]
    UserName: UserName


class CreateUserResponse(TypedDict, total=False):
    ServerId: ServerId
    UserName: UserName


class S3Tag(TypedDict, total=False):
    Key: S3TagKey
    Value: S3TagValue


S3Tags = List[S3Tag]


class TagStepDetails(TypedDict, total=False):
    Name: Optional[WorkflowStepName]
    Tags: Optional[S3Tags]
    SourceFileLocation: Optional[SourceFileLocation]


class DeleteStepDetails(TypedDict, total=False):
    Name: Optional[WorkflowStepName]
    SourceFileLocation: Optional[SourceFileLocation]


class CustomStepDetails(TypedDict, total=False):
    Name: Optional[WorkflowStepName]
    Target: Optional[CustomStepTarget]
    TimeoutSeconds: Optional[CustomStepTimeoutSeconds]
    SourceFileLocation: Optional[SourceFileLocation]


class WorkflowStep(TypedDict, total=False):
    Type: Optional[WorkflowStepType]
    CopyStepDetails: Optional[CopyStepDetails]
    CustomStepDetails: Optional[CustomStepDetails]
    DeleteStepDetails: Optional[DeleteStepDetails]
    TagStepDetails: Optional[TagStepDetails]


WorkflowSteps = List[WorkflowStep]


class CreateWorkflowRequest(ServiceRequest):
    Description: Optional[WorkflowDescription]
    Steps: WorkflowSteps
    OnExceptionSteps: Optional[WorkflowSteps]
    Tags: Optional[Tags]


class CreateWorkflowResponse(TypedDict, total=False):
    WorkflowId: WorkflowId


DateImported = datetime


class DeleteAccessRequest(ServiceRequest):
    ServerId: ServerId
    ExternalId: ExternalId


class DeleteServerRequest(ServiceRequest):
    ServerId: ServerId


class DeleteSshPublicKeyRequest(ServiceRequest):
    ServerId: ServerId
    SshPublicKeyId: SshPublicKeyId
    UserName: UserName


class DeleteUserRequest(ServiceRequest):
    ServerId: ServerId
    UserName: UserName


class DeleteWorkflowRequest(ServiceRequest):
    WorkflowId: WorkflowId


class DescribeAccessRequest(ServiceRequest):
    ServerId: ServerId
    ExternalId: ExternalId


class DescribedAccess(TypedDict, total=False):
    HomeDirectory: Optional[HomeDirectory]
    HomeDirectoryMappings: Optional[HomeDirectoryMappings]
    HomeDirectoryType: Optional[HomeDirectoryType]
    Policy: Optional[Policy]
    PosixProfile: Optional[PosixProfile]
    Role: Optional[Role]
    ExternalId: Optional[ExternalId]


class DescribeAccessResponse(TypedDict, total=False):
    ServerId: ServerId
    Access: DescribedAccess


class DescribeExecutionRequest(ServiceRequest):
    ExecutionId: ExecutionId
    WorkflowId: WorkflowId


class ExecutionError(TypedDict, total=False):
    Type: ExecutionErrorType
    Message: ExecutionErrorMessage


class ExecutionStepResult(TypedDict, total=False):
    StepType: Optional[WorkflowStepType]
    Outputs: Optional[StepResultOutputsJson]
    Error: Optional[ExecutionError]


ExecutionStepResults = List[ExecutionStepResult]


class ExecutionResults(TypedDict, total=False):
    Steps: Optional[ExecutionStepResults]
    OnExceptionSteps: Optional[ExecutionStepResults]


class LoggingConfiguration(TypedDict, total=False):
    LoggingRole: Optional[Role]
    LogGroupName: Optional[LogGroupName]


class UserDetails(TypedDict, total=False):
    UserName: UserName
    ServerId: ServerId
    SessionId: Optional[SessionId]


class ServiceMetadata(TypedDict, total=False):
    UserDetails: UserDetails


class S3FileLocation(TypedDict, total=False):
    Bucket: Optional[S3Bucket]
    Key: Optional[S3Key]
    VersionId: Optional[S3VersionId]
    Etag: Optional[S3Etag]


class FileLocation(TypedDict, total=False):
    S3FileLocation: Optional[S3FileLocation]
    EfsFileLocation: Optional[EfsFileLocation]


class DescribedExecution(TypedDict, total=False):
    ExecutionId: Optional[ExecutionId]
    InitialFileLocation: Optional[FileLocation]
    ServiceMetadata: Optional[ServiceMetadata]
    ExecutionRole: Optional[Role]
    LoggingConfiguration: Optional[LoggingConfiguration]
    PosixProfile: Optional[PosixProfile]
    Status: Optional[ExecutionStatus]
    Results: Optional[ExecutionResults]


class DescribeExecutionResponse(TypedDict, total=False):
    WorkflowId: WorkflowId
    Execution: DescribedExecution


class DescribeSecurityPolicyRequest(ServiceRequest):
    SecurityPolicyName: SecurityPolicyName


SecurityPolicyOptions = List[SecurityPolicyOption]


class DescribedSecurityPolicy(TypedDict, total=False):
    Fips: Optional[Fips]
    SecurityPolicyName: SecurityPolicyName
    SshCiphers: Optional[SecurityPolicyOptions]
    SshKexs: Optional[SecurityPolicyOptions]
    SshMacs: Optional[SecurityPolicyOptions]
    TlsCiphers: Optional[SecurityPolicyOptions]


class DescribeSecurityPolicyResponse(TypedDict, total=False):
    SecurityPolicy: DescribedSecurityPolicy


class DescribeServerRequest(ServiceRequest):
    ServerId: ServerId


class DescribedServer(TypedDict, total=False):
    Arn: Arn
    Certificate: Optional[Certificate]
    ProtocolDetails: Optional[ProtocolDetails]
    Domain: Optional[Domain]
    EndpointDetails: Optional[EndpointDetails]
    EndpointType: Optional[EndpointType]
    HostKeyFingerprint: Optional[HostKeyFingerprint]
    IdentityProviderDetails: Optional[IdentityProviderDetails]
    IdentityProviderType: Optional[IdentityProviderType]
    LoggingRole: Optional[Role]
    PostAuthenticationLoginBanner: Optional[PostAuthenticationLoginBanner]
    PreAuthenticationLoginBanner: Optional[PreAuthenticationLoginBanner]
    Protocols: Optional[Protocols]
    SecurityPolicyName: Optional[SecurityPolicyName]
    ServerId: Optional[ServerId]
    State: Optional[State]
    Tags: Optional[Tags]
    UserCount: Optional[UserCount]
    WorkflowDetails: Optional[WorkflowDetails]


class DescribeServerResponse(TypedDict, total=False):
    Server: DescribedServer


class DescribeUserRequest(ServiceRequest):
    ServerId: ServerId
    UserName: UserName


class SshPublicKey(TypedDict, total=False):
    DateImported: DateImported
    SshPublicKeyBody: SshPublicKeyBody
    SshPublicKeyId: SshPublicKeyId


SshPublicKeys = List[SshPublicKey]


class DescribedUser(TypedDict, total=False):
    Arn: Arn
    HomeDirectory: Optional[HomeDirectory]
    HomeDirectoryMappings: Optional[HomeDirectoryMappings]
    HomeDirectoryType: Optional[HomeDirectoryType]
    Policy: Optional[Policy]
    PosixProfile: Optional[PosixProfile]
    Role: Optional[Role]
    SshPublicKeys: Optional[SshPublicKeys]
    Tags: Optional[Tags]
    UserName: Optional[UserName]


class DescribeUserResponse(TypedDict, total=False):
    ServerId: ServerId
    User: DescribedUser


class DescribeWorkflowRequest(ServiceRequest):
    WorkflowId: WorkflowId


class DescribedWorkflow(TypedDict, total=False):
    Arn: Arn
    Description: Optional[WorkflowDescription]
    Steps: Optional[WorkflowSteps]
    OnExceptionSteps: Optional[WorkflowSteps]
    WorkflowId: Optional[WorkflowId]
    Tags: Optional[Tags]


class DescribeWorkflowResponse(TypedDict, total=False):
    Workflow: DescribedWorkflow


class ImportSshPublicKeyRequest(ServiceRequest):
    ServerId: ServerId
    SshPublicKeyBody: SshPublicKeyBody
    UserName: UserName


class ImportSshPublicKeyResponse(TypedDict, total=False):
    ServerId: ServerId
    SshPublicKeyId: SshPublicKeyId
    UserName: UserName


class ListAccessesRequest(ServiceRequest):
    MaxResults: Optional[MaxResults]
    NextToken: Optional[NextToken]
    ServerId: ServerId


class ListedAccess(TypedDict, total=False):
    HomeDirectory: Optional[HomeDirectory]
    HomeDirectoryType: Optional[HomeDirectoryType]
    Role: Optional[Role]
    ExternalId: Optional[ExternalId]


ListedAccesses = List[ListedAccess]


class ListAccessesResponse(TypedDict, total=False):
    NextToken: Optional[NextToken]
    ServerId: ServerId
    Accesses: ListedAccesses


class ListExecutionsRequest(ServiceRequest):
    MaxResults: Optional[MaxResults]
    NextToken: Optional[NextToken]
    WorkflowId: WorkflowId


class ListedExecution(TypedDict, total=False):
    ExecutionId: Optional[ExecutionId]
    InitialFileLocation: Optional[FileLocation]
    ServiceMetadata: Optional[ServiceMetadata]
    Status: Optional[ExecutionStatus]


ListedExecutions = List[ListedExecution]


class ListExecutionsResponse(TypedDict, total=False):
    NextToken: Optional[NextToken]
    WorkflowId: WorkflowId
    Executions: ListedExecutions


class ListSecurityPoliciesRequest(ServiceRequest):
    MaxResults: Optional[MaxResults]
    NextToken: Optional[NextToken]


SecurityPolicyNames = List[SecurityPolicyName]


class ListSecurityPoliciesResponse(TypedDict, total=False):
    NextToken: Optional[NextToken]
    SecurityPolicyNames: SecurityPolicyNames


class ListServersRequest(ServiceRequest):
    MaxResults: Optional[MaxResults]
    NextToken: Optional[NextToken]


class ListedServer(TypedDict, total=False):
    Arn: Arn
    Domain: Optional[Domain]
    IdentityProviderType: Optional[IdentityProviderType]
    EndpointType: Optional[EndpointType]
    LoggingRole: Optional[Role]
    ServerId: Optional[ServerId]
    State: Optional[State]
    UserCount: Optional[UserCount]


ListedServers = List[ListedServer]


class ListServersResponse(TypedDict, total=False):
    NextToken: Optional[NextToken]
    Servers: ListedServers


class ListTagsForResourceRequest(ServiceRequest):
    Arn: Arn
    MaxResults: Optional[MaxResults]
    NextToken: Optional[NextToken]


class ListTagsForResourceResponse(TypedDict, total=False):
    Arn: Optional[Arn]
    NextToken: Optional[NextToken]
    Tags: Optional[Tags]


class ListUsersRequest(ServiceRequest):
    MaxResults: Optional[MaxResults]
    NextToken: Optional[NextToken]
    ServerId: ServerId


class ListedUser(TypedDict, total=False):
    Arn: Arn
    HomeDirectory: Optional[HomeDirectory]
    HomeDirectoryType: Optional[HomeDirectoryType]
    Role: Optional[Role]
    SshPublicKeyCount: Optional[SshPublicKeyCount]
    UserName: Optional[UserName]


ListedUsers = List[ListedUser]


class ListUsersResponse(TypedDict, total=False):
    NextToken: Optional[NextToken]
    ServerId: ServerId
    Users: ListedUsers


class ListWorkflowsRequest(ServiceRequest):
    MaxResults: Optional[MaxResults]
    NextToken: Optional[NextToken]


class ListedWorkflow(TypedDict, total=False):
    WorkflowId: Optional[WorkflowId]
    Description: Optional[WorkflowDescription]
    Arn: Optional[Arn]


ListedWorkflows = List[ListedWorkflow]


class ListWorkflowsResponse(TypedDict, total=False):
    NextToken: Optional[NextToken]
    Workflows: ListedWorkflows


class SendWorkflowStepStateRequest(ServiceRequest):
    WorkflowId: WorkflowId
    ExecutionId: ExecutionId
    Token: CallbackToken
    Status: CustomStepStatus


class SendWorkflowStepStateResponse(TypedDict, total=False):
    pass


class StartServerRequest(ServiceRequest):
    ServerId: ServerId


class StopServerRequest(ServiceRequest):
    ServerId: ServerId


TagKeys = List[TagKey]


class TagResourceRequest(ServiceRequest):
    Arn: Arn
    Tags: Tags


class TestIdentityProviderRequest(ServiceRequest):
    ServerId: ServerId
    ServerProtocol: Optional[Protocol]
    SourceIp: Optional[SourceIp]
    UserName: UserName
    UserPassword: Optional[UserPassword]


class TestIdentityProviderResponse(TypedDict, total=False):
    Response: Optional[Response]
    StatusCode: StatusCode
    Message: Optional[Message]
    Url: Url


class UntagResourceRequest(ServiceRequest):
    Arn: Arn
    TagKeys: TagKeys


class UpdateAccessRequest(ServiceRequest):
    HomeDirectory: Optional[HomeDirectory]
    HomeDirectoryType: Optional[HomeDirectoryType]
    HomeDirectoryMappings: Optional[HomeDirectoryMappings]
    Policy: Optional[Policy]
    PosixProfile: Optional[PosixProfile]
    Role: Optional[Role]
    ServerId: ServerId
    ExternalId: ExternalId


class UpdateAccessResponse(TypedDict, total=False):
    ServerId: ServerId
    ExternalId: ExternalId


class UpdateServerRequest(ServiceRequest):
    Certificate: Optional[Certificate]
    ProtocolDetails: Optional[ProtocolDetails]
    EndpointDetails: Optional[EndpointDetails]
    EndpointType: Optional[EndpointType]
    HostKey: Optional[HostKey]
    IdentityProviderDetails: Optional[IdentityProviderDetails]
    LoggingRole: Optional[NullableRole]
    PostAuthenticationLoginBanner: Optional[PostAuthenticationLoginBanner]
    PreAuthenticationLoginBanner: Optional[PreAuthenticationLoginBanner]
    Protocols: Optional[Protocols]
    SecurityPolicyName: Optional[SecurityPolicyName]
    ServerId: ServerId
    WorkflowDetails: Optional[WorkflowDetails]


class UpdateServerResponse(TypedDict, total=False):
    ServerId: ServerId


class UpdateUserRequest(ServiceRequest):
    HomeDirectory: Optional[HomeDirectory]
    HomeDirectoryType: Optional[HomeDirectoryType]
    HomeDirectoryMappings: Optional[HomeDirectoryMappings]
    Policy: Optional[Policy]
    PosixProfile: Optional[PosixProfile]
    Role: Optional[Role]
    ServerId: ServerId
    UserName: UserName


class UpdateUserResponse(TypedDict, total=False):
    ServerId: ServerId
    UserName: UserName


class TransferApi:

    service = "transfer"
    version = "2018-11-05"

    @handler("CreateAccess")
    def create_access(
        self,
        context: RequestContext,
        role: Role,
        server_id: ServerId,
        external_id: ExternalId,
        home_directory: HomeDirectory = None,
        home_directory_type: HomeDirectoryType = None,
        home_directory_mappings: HomeDirectoryMappings = None,
        policy: Policy = None,
        posix_profile: PosixProfile = None,
    ) -> CreateAccessResponse:
        raise NotImplementedError

    @handler("CreateServer")
    def create_server(
        self,
        context: RequestContext,
        certificate: Certificate = None,
        domain: Domain = None,
        endpoint_details: EndpointDetails = None,
        endpoint_type: EndpointType = None,
        host_key: HostKey = None,
        identity_provider_details: IdentityProviderDetails = None,
        identity_provider_type: IdentityProviderType = None,
        logging_role: Role = None,
        post_authentication_login_banner: PostAuthenticationLoginBanner = None,
        pre_authentication_login_banner: PreAuthenticationLoginBanner = None,
        protocols: Protocols = None,
        protocol_details: ProtocolDetails = None,
        security_policy_name: SecurityPolicyName = None,
        tags: Tags = None,
        workflow_details: WorkflowDetails = None,
    ) -> CreateServerResponse:
        raise NotImplementedError

    @handler("CreateUser")
    def create_user(
        self,
        context: RequestContext,
        role: Role,
        server_id: ServerId,
        user_name: UserName,
        home_directory: HomeDirectory = None,
        home_directory_type: HomeDirectoryType = None,
        home_directory_mappings: HomeDirectoryMappings = None,
        policy: Policy = None,
        posix_profile: PosixProfile = None,
        ssh_public_key_body: SshPublicKeyBody = None,
        tags: Tags = None,
    ) -> CreateUserResponse:
        raise NotImplementedError

    @handler("CreateWorkflow")
    def create_workflow(
        self,
        context: RequestContext,
        steps: WorkflowSteps,
        description: WorkflowDescription = None,
        on_exception_steps: WorkflowSteps = None,
        tags: Tags = None,
    ) -> CreateWorkflowResponse:
        raise NotImplementedError

    @handler("DeleteAccess")
    def delete_access(
        self, context: RequestContext, server_id: ServerId, external_id: ExternalId
    ) -> None:
        raise NotImplementedError

    @handler("DeleteServer")
    def delete_server(self, context: RequestContext, server_id: ServerId) -> None:
        raise NotImplementedError

    @handler("DeleteSshPublicKey")
    def delete_ssh_public_key(
        self,
        context: RequestContext,
        server_id: ServerId,
        ssh_public_key_id: SshPublicKeyId,
        user_name: UserName,
    ) -> None:
        raise NotImplementedError

    @handler("DeleteUser")
    def delete_user(
        self, context: RequestContext, server_id: ServerId, user_name: UserName
    ) -> None:
        raise NotImplementedError

    @handler("DeleteWorkflow")
    def delete_workflow(self, context: RequestContext, workflow_id: WorkflowId) -> None:
        raise NotImplementedError

    @handler("DescribeAccess")
    def describe_access(
        self, context: RequestContext, server_id: ServerId, external_id: ExternalId
    ) -> DescribeAccessResponse:
        raise NotImplementedError

    @handler("DescribeExecution")
    def describe_execution(
        self, context: RequestContext, execution_id: ExecutionId, workflow_id: WorkflowId
    ) -> DescribeExecutionResponse:
        raise NotImplementedError

    @handler("DescribeSecurityPolicy")
    def describe_security_policy(
        self, context: RequestContext, security_policy_name: SecurityPolicyName
    ) -> DescribeSecurityPolicyResponse:
        raise NotImplementedError

    @handler("DescribeServer")
    def describe_server(
        self, context: RequestContext, server_id: ServerId
    ) -> DescribeServerResponse:
        raise NotImplementedError

    @handler("DescribeUser")
    def describe_user(
        self, context: RequestContext, server_id: ServerId, user_name: UserName
    ) -> DescribeUserResponse:
        raise NotImplementedError

    @handler("DescribeWorkflow")
    def describe_workflow(
        self, context: RequestContext, workflow_id: WorkflowId
    ) -> DescribeWorkflowResponse:
        raise NotImplementedError

    @handler("ImportSshPublicKey")
    def import_ssh_public_key(
        self,
        context: RequestContext,
        server_id: ServerId,
        ssh_public_key_body: SshPublicKeyBody,
        user_name: UserName,
    ) -> ImportSshPublicKeyResponse:
        raise NotImplementedError

    @handler("ListAccesses")
    def list_accesses(
        self,
        context: RequestContext,
        server_id: ServerId,
        max_results: MaxResults = None,
        next_token: NextToken = None,
    ) -> ListAccessesResponse:
        raise NotImplementedError

    @handler("ListExecutions")
    def list_executions(
        self,
        context: RequestContext,
        workflow_id: WorkflowId,
        max_results: MaxResults = None,
        next_token: NextToken = None,
    ) -> ListExecutionsResponse:
        raise NotImplementedError

    @handler("ListSecurityPolicies")
    def list_security_policies(
        self, context: RequestContext, max_results: MaxResults = None, next_token: NextToken = None
    ) -> ListSecurityPoliciesResponse:
        raise NotImplementedError

    @handler("ListServers")
    def list_servers(
        self, context: RequestContext, max_results: MaxResults = None, next_token: NextToken = None
    ) -> ListServersResponse:
        raise NotImplementedError

    @handler("ListTagsForResource")
    def list_tags_for_resource(
        self,
        context: RequestContext,
        arn: Arn,
        max_results: MaxResults = None,
        next_token: NextToken = None,
    ) -> ListTagsForResourceResponse:
        raise NotImplementedError

    @handler("ListUsers")
    def list_users(
        self,
        context: RequestContext,
        server_id: ServerId,
        max_results: MaxResults = None,
        next_token: NextToken = None,
    ) -> ListUsersResponse:
        raise NotImplementedError

    @handler("ListWorkflows")
    def list_workflows(
        self, context: RequestContext, max_results: MaxResults = None, next_token: NextToken = None
    ) -> ListWorkflowsResponse:
        raise NotImplementedError

    @handler("SendWorkflowStepState")
    def send_workflow_step_state(
        self,
        context: RequestContext,
        workflow_id: WorkflowId,
        execution_id: ExecutionId,
        token: CallbackToken,
        status: CustomStepStatus,
    ) -> SendWorkflowStepStateResponse:
        raise NotImplementedError

    @handler("StartServer")
    def start_server(self, context: RequestContext, server_id: ServerId) -> None:
        raise NotImplementedError

    @handler("StopServer")
    def stop_server(self, context: RequestContext, server_id: ServerId) -> None:
        raise NotImplementedError

    @handler("TagResource")
    def tag_resource(self, context: RequestContext, arn: Arn, tags: Tags) -> None:
        raise NotImplementedError

    @handler("TestIdentityProvider")
    def test_identity_provider(
        self,
        context: RequestContext,
        server_id: ServerId,
        user_name: UserName,
        server_protocol: Protocol = None,
        source_ip: SourceIp = None,
        user_password: UserPassword = None,
    ) -> TestIdentityProviderResponse:
        raise NotImplementedError

    @handler("UntagResource")
    def untag_resource(self, context: RequestContext, arn: Arn, tag_keys: TagKeys) -> None:
        raise NotImplementedError

    @handler("UpdateAccess")
    def update_access(
        self,
        context: RequestContext,
        server_id: ServerId,
        external_id: ExternalId,
        home_directory: HomeDirectory = None,
        home_directory_type: HomeDirectoryType = None,
        home_directory_mappings: HomeDirectoryMappings = None,
        policy: Policy = None,
        posix_profile: PosixProfile = None,
        role: Role = None,
    ) -> UpdateAccessResponse:
        raise NotImplementedError

    @handler("UpdateServer")
    def update_server(
        self,
        context: RequestContext,
        server_id: ServerId,
        certificate: Certificate = None,
        protocol_details: ProtocolDetails = None,
        endpoint_details: EndpointDetails = None,
        endpoint_type: EndpointType = None,
        host_key: HostKey = None,
        identity_provider_details: IdentityProviderDetails = None,
        logging_role: NullableRole = None,
        post_authentication_login_banner: PostAuthenticationLoginBanner = None,
        pre_authentication_login_banner: PreAuthenticationLoginBanner = None,
        protocols: Protocols = None,
        security_policy_name: SecurityPolicyName = None,
        workflow_details: WorkflowDetails = None,
    ) -> UpdateServerResponse:
        raise NotImplementedError

    @handler("UpdateUser")
    def update_user(
        self,
        context: RequestContext,
        server_id: ServerId,
        user_name: UserName,
        home_directory: HomeDirectory = None,
        home_directory_type: HomeDirectoryType = None,
        home_directory_mappings: HomeDirectoryMappings = None,
        policy: Policy = None,
        posix_profile: PosixProfile = None,
        role: Role = None,
    ) -> UpdateUserResponse:
        raise NotImplementedError
