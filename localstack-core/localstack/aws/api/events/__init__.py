from datetime import datetime
from enum import StrEnum
from typing import TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

AccountId = str
Action = str
ApiDestinationArn = str
ApiDestinationDescription = str
ApiDestinationInvocationRateLimitPerSecond = int
ApiDestinationName = str
ArchiveArn = str
ArchiveDescription = str
ArchiveName = str
ArchiveStateReason = str
Arn = str
AuthHeaderParameters = str
AuthHeaderParametersSensitive = str
Boolean = bool
CapacityProvider = str
CapacityProviderStrategyItemBase = int
CapacityProviderStrategyItemWeight = int
ConnectionArn = str
ConnectionDescription = str
ConnectionName = str
ConnectionStateReason = str
CreatedBy = str
Database = str
DbUser = str
EndpointArn = str
EndpointDescription = str
EndpointId = str
EndpointName = str
EndpointStateReason = str
EndpointUrl = str
ErrorCode = str
ErrorMessage = str
EventBusArn = str
EventBusDescription = str
EventBusName = str
EventBusNameOrArn = str
EventId = str
EventPattern = str
EventResource = str
EventSourceName = str
EventSourceNamePrefix = str
GraphQLOperation = str
HeaderKey = str
HeaderValue = str
HeaderValueSensitive = str
HealthCheck = str
HomeRegion = str
HttpsEndpoint = str
IamRoleArn = str
InputTransformerPathKey = str
Integer = int
KmsKeyIdentifier = str
LimitMax100 = int
LimitMin1 = int
ManagedBy = str
MaximumEventAgeInSeconds = int
MaximumRetryAttempts = int
MessageGroupId = str
NextToken = str
NonPartnerEventBusArn = str
NonPartnerEventBusName = str
NonPartnerEventBusNameOrArn = str
PartnerEventSourceNamePrefix = str
PathParameter = str
PlacementConstraintExpression = str
PlacementStrategyField = str
Principal = str
QueryStringKey = str
QueryStringValue = str
QueryStringValueSensitive = str
RedshiftSecretManagerArn = str
ReferenceId = str
ReplayArn = str
ReplayDescription = str
ReplayName = str
ReplayStateReason = str
ResourceArn = str
ResourceAssociationArn = str
ResourceConfigurationArn = str
RetentionDays = int
RoleArn = str
Route = str
RuleArn = str
RuleDescription = str
RuleName = str
RunCommandTargetKey = str
RunCommandTargetValue = str
SageMakerPipelineParameterName = str
SageMakerPipelineParameterValue = str
ScheduleExpression = str
SecretsManagerSecretArn = str
SensitiveString = str
Sql = str
StatementId = str
StatementName = str
String = str
TagKey = str
TagValue = str
TargetArn = str
TargetId = str
TargetInput = str
TargetInputPath = str
TargetPartitionKeyPath = str
TraceHeader = str
TransformerInput = str


class ApiDestinationHttpMethod(StrEnum):
    POST = "POST"
    GET = "GET"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"


class ApiDestinationState(StrEnum):
    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"


class ArchiveState(StrEnum):
    ENABLED = "ENABLED"
    DISABLED = "DISABLED"
    CREATING = "CREATING"
    UPDATING = "UPDATING"
    CREATE_FAILED = "CREATE_FAILED"
    UPDATE_FAILED = "UPDATE_FAILED"


class AssignPublicIp(StrEnum):
    ENABLED = "ENABLED"
    DISABLED = "DISABLED"


class ConnectionAuthorizationType(StrEnum):
    BASIC = "BASIC"
    OAUTH_CLIENT_CREDENTIALS = "OAUTH_CLIENT_CREDENTIALS"
    API_KEY = "API_KEY"


class ConnectionOAuthHttpMethod(StrEnum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"


class ConnectionState(StrEnum):
    CREATING = "CREATING"
    UPDATING = "UPDATING"
    DELETING = "DELETING"
    AUTHORIZED = "AUTHORIZED"
    DEAUTHORIZED = "DEAUTHORIZED"
    AUTHORIZING = "AUTHORIZING"
    DEAUTHORIZING = "DEAUTHORIZING"
    ACTIVE = "ACTIVE"
    FAILED_CONNECTIVITY = "FAILED_CONNECTIVITY"


class EndpointState(StrEnum):
    ACTIVE = "ACTIVE"
    CREATING = "CREATING"
    UPDATING = "UPDATING"
    DELETING = "DELETING"
    CREATE_FAILED = "CREATE_FAILED"
    UPDATE_FAILED = "UPDATE_FAILED"
    DELETE_FAILED = "DELETE_FAILED"


class EventSourceState(StrEnum):
    PENDING = "PENDING"
    ACTIVE = "ACTIVE"
    DELETED = "DELETED"


class IncludeDetail(StrEnum):
    NONE = "NONE"
    FULL = "FULL"


class LaunchType(StrEnum):
    EC2 = "EC2"
    FARGATE = "FARGATE"
    EXTERNAL = "EXTERNAL"


class Level(StrEnum):
    OFF = "OFF"
    ERROR = "ERROR"
    INFO = "INFO"
    TRACE = "TRACE"


class PlacementConstraintType(StrEnum):
    distinctInstance = "distinctInstance"
    memberOf = "memberOf"


class PlacementStrategyType(StrEnum):
    random = "random"
    spread = "spread"
    binpack = "binpack"


class PropagateTags(StrEnum):
    TASK_DEFINITION = "TASK_DEFINITION"


class ReplayState(StrEnum):
    STARTING = "STARTING"
    RUNNING = "RUNNING"
    CANCELLING = "CANCELLING"
    COMPLETED = "COMPLETED"
    CANCELLED = "CANCELLED"
    FAILED = "FAILED"


class ReplicationState(StrEnum):
    ENABLED = "ENABLED"
    DISABLED = "DISABLED"


class RuleState(StrEnum):
    ENABLED = "ENABLED"
    DISABLED = "DISABLED"
    ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS = "ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS"


class AccessDeniedException(ServiceException):
    code: str = "AccessDeniedException"
    sender_fault: bool = False
    status_code: int = 400


class ConcurrentModificationException(ServiceException):
    code: str = "ConcurrentModificationException"
    sender_fault: bool = False
    status_code: int = 400


class IllegalStatusException(ServiceException):
    code: str = "IllegalStatusException"
    sender_fault: bool = False
    status_code: int = 400


class InternalException(ServiceException):
    code: str = "InternalException"
    sender_fault: bool = False
    status_code: int = 400


class InvalidEventPatternException(ServiceException):
    code: str = "InvalidEventPatternException"
    sender_fault: bool = False
    status_code: int = 400


class InvalidStateException(ServiceException):
    code: str = "InvalidStateException"
    sender_fault: bool = False
    status_code: int = 400


class LimitExceededException(ServiceException):
    code: str = "LimitExceededException"
    sender_fault: bool = False
    status_code: int = 400


class ManagedRuleException(ServiceException):
    code: str = "ManagedRuleException"
    sender_fault: bool = False
    status_code: int = 400


class OperationDisabledException(ServiceException):
    code: str = "OperationDisabledException"
    sender_fault: bool = False
    status_code: int = 400


class PolicyLengthExceededException(ServiceException):
    code: str = "PolicyLengthExceededException"
    sender_fault: bool = False
    status_code: int = 400


class ResourceAlreadyExistsException(ServiceException):
    code: str = "ResourceAlreadyExistsException"
    sender_fault: bool = False
    status_code: int = 400


class ResourceNotFoundException(ServiceException):
    code: str = "ResourceNotFoundException"
    sender_fault: bool = False
    status_code: int = 400


class ThrottlingException(ServiceException):
    code: str = "ThrottlingException"
    sender_fault: bool = False
    status_code: int = 400


class ActivateEventSourceRequest(ServiceRequest):
    Name: EventSourceName


Timestamp = datetime


class ApiDestination(TypedDict, total=False):
    ApiDestinationArn: ApiDestinationArn | None
    Name: ApiDestinationName | None
    ApiDestinationState: ApiDestinationState | None
    ConnectionArn: ConnectionArn | None
    InvocationEndpoint: HttpsEndpoint | None
    HttpMethod: ApiDestinationHttpMethod | None
    InvocationRateLimitPerSecond: ApiDestinationInvocationRateLimitPerSecond | None
    CreationTime: Timestamp | None
    LastModifiedTime: Timestamp | None


ApiDestinationResponseList = list[ApiDestination]


class AppSyncParameters(TypedDict, total=False):
    GraphQLOperation: GraphQLOperation | None


Long = int


class Archive(TypedDict, total=False):
    ArchiveName: ArchiveName | None
    EventSourceArn: EventBusArn | None
    State: ArchiveState | None
    StateReason: ArchiveStateReason | None
    RetentionDays: RetentionDays | None
    SizeBytes: Long | None
    EventCount: Long | None
    CreationTime: Timestamp | None


ArchiveResponseList = list[Archive]
StringList = list[String]


class AwsVpcConfiguration(TypedDict, total=False):
    Subnets: StringList
    SecurityGroups: StringList | None
    AssignPublicIp: AssignPublicIp | None


class BatchArrayProperties(TypedDict, total=False):
    Size: Integer | None


class BatchRetryStrategy(TypedDict, total=False):
    Attempts: Integer | None


class BatchParameters(TypedDict, total=False):
    JobDefinition: String
    JobName: String
    ArrayProperties: BatchArrayProperties | None
    RetryStrategy: BatchRetryStrategy | None


class CancelReplayRequest(ServiceRequest):
    ReplayName: ReplayName


class CancelReplayResponse(TypedDict, total=False):
    ReplayArn: ReplayArn | None
    State: ReplayState | None
    StateReason: ReplayStateReason | None


class CapacityProviderStrategyItem(TypedDict, total=False):
    capacityProvider: CapacityProvider
    weight: CapacityProviderStrategyItemWeight | None
    base: CapacityProviderStrategyItemBase | None


CapacityProviderStrategy = list[CapacityProviderStrategyItem]


class Condition(TypedDict, total=False):
    Type: String
    Key: String
    Value: String


class Connection(TypedDict, total=False):
    ConnectionArn: ConnectionArn | None
    Name: ConnectionName | None
    ConnectionState: ConnectionState | None
    StateReason: ConnectionStateReason | None
    AuthorizationType: ConnectionAuthorizationType | None
    CreationTime: Timestamp | None
    LastModifiedTime: Timestamp | None
    LastAuthorizedTime: Timestamp | None


class ConnectionApiKeyAuthResponseParameters(TypedDict, total=False):
    ApiKeyName: AuthHeaderParameters | None


class DescribeConnectionResourceParameters(TypedDict, total=False):
    ResourceConfigurationArn: ResourceConfigurationArn
    ResourceAssociationArn: ResourceAssociationArn


class DescribeConnectionConnectivityParameters(TypedDict, total=False):
    ResourceParameters: DescribeConnectionResourceParameters


class ConnectionBodyParameter(TypedDict, total=False):
    Key: String | None
    Value: SensitiveString | None
    IsValueSecret: Boolean | None


ConnectionBodyParametersList = list[ConnectionBodyParameter]


class ConnectionQueryStringParameter(TypedDict, total=False):
    Key: QueryStringKey | None
    Value: QueryStringValueSensitive | None
    IsValueSecret: Boolean | None


ConnectionQueryStringParametersList = list[ConnectionQueryStringParameter]


class ConnectionHeaderParameter(TypedDict, total=False):
    Key: HeaderKey | None
    Value: HeaderValueSensitive | None
    IsValueSecret: Boolean | None


ConnectionHeaderParametersList = list[ConnectionHeaderParameter]


class ConnectionHttpParameters(TypedDict, total=False):
    HeaderParameters: ConnectionHeaderParametersList | None
    QueryStringParameters: ConnectionQueryStringParametersList | None
    BodyParameters: ConnectionBodyParametersList | None


class ConnectionOAuthClientResponseParameters(TypedDict, total=False):
    ClientID: AuthHeaderParameters | None


class ConnectionOAuthResponseParameters(TypedDict, total=False):
    ClientParameters: ConnectionOAuthClientResponseParameters | None
    AuthorizationEndpoint: HttpsEndpoint | None
    HttpMethod: ConnectionOAuthHttpMethod | None
    OAuthHttpParameters: ConnectionHttpParameters | None


class ConnectionBasicAuthResponseParameters(TypedDict, total=False):
    Username: AuthHeaderParameters | None


class ConnectionAuthResponseParameters(TypedDict, total=False):
    BasicAuthParameters: ConnectionBasicAuthResponseParameters | None
    OAuthParameters: ConnectionOAuthResponseParameters | None
    ApiKeyAuthParameters: ConnectionApiKeyAuthResponseParameters | None
    InvocationHttpParameters: ConnectionHttpParameters | None
    ConnectivityParameters: DescribeConnectionConnectivityParameters | None


ConnectionResponseList = list[Connection]


class ConnectivityResourceConfigurationArn(TypedDict, total=False):
    ResourceConfigurationArn: ResourceConfigurationArn


class ConnectivityResourceParameters(TypedDict, total=False):
    ResourceParameters: ConnectivityResourceConfigurationArn


class CreateApiDestinationRequest(ServiceRequest):
    Name: ApiDestinationName
    Description: ApiDestinationDescription | None
    ConnectionArn: ConnectionArn
    InvocationEndpoint: HttpsEndpoint
    HttpMethod: ApiDestinationHttpMethod
    InvocationRateLimitPerSecond: ApiDestinationInvocationRateLimitPerSecond | None


class CreateApiDestinationResponse(TypedDict, total=False):
    ApiDestinationArn: ApiDestinationArn | None
    ApiDestinationState: ApiDestinationState | None
    CreationTime: Timestamp | None
    LastModifiedTime: Timestamp | None


class CreateArchiveRequest(ServiceRequest):
    ArchiveName: ArchiveName
    EventSourceArn: EventBusArn
    Description: ArchiveDescription | None
    EventPattern: EventPattern | None
    RetentionDays: RetentionDays | None
    KmsKeyIdentifier: KmsKeyIdentifier | None


class CreateArchiveResponse(TypedDict, total=False):
    ArchiveArn: ArchiveArn | None
    State: ArchiveState | None
    StateReason: ArchiveStateReason | None
    CreationTime: Timestamp | None


class CreateConnectionApiKeyAuthRequestParameters(TypedDict, total=False):
    ApiKeyName: AuthHeaderParameters
    ApiKeyValue: AuthHeaderParametersSensitive


class CreateConnectionOAuthClientRequestParameters(TypedDict, total=False):
    ClientID: AuthHeaderParameters
    ClientSecret: AuthHeaderParametersSensitive


class CreateConnectionOAuthRequestParameters(TypedDict, total=False):
    ClientParameters: CreateConnectionOAuthClientRequestParameters
    AuthorizationEndpoint: HttpsEndpoint
    HttpMethod: ConnectionOAuthHttpMethod
    OAuthHttpParameters: ConnectionHttpParameters | None


class CreateConnectionBasicAuthRequestParameters(TypedDict, total=False):
    Username: AuthHeaderParameters
    Password: AuthHeaderParametersSensitive


class CreateConnectionAuthRequestParameters(TypedDict, total=False):
    BasicAuthParameters: CreateConnectionBasicAuthRequestParameters | None
    OAuthParameters: CreateConnectionOAuthRequestParameters | None
    ApiKeyAuthParameters: CreateConnectionApiKeyAuthRequestParameters | None
    InvocationHttpParameters: ConnectionHttpParameters | None
    ConnectivityParameters: ConnectivityResourceParameters | None


class CreateConnectionRequest(ServiceRequest):
    Name: ConnectionName
    Description: ConnectionDescription | None
    AuthorizationType: ConnectionAuthorizationType
    AuthParameters: CreateConnectionAuthRequestParameters
    InvocationConnectivityParameters: ConnectivityResourceParameters | None
    KmsKeyIdentifier: KmsKeyIdentifier | None


class CreateConnectionResponse(TypedDict, total=False):
    ConnectionArn: ConnectionArn | None
    ConnectionState: ConnectionState | None
    CreationTime: Timestamp | None
    LastModifiedTime: Timestamp | None


class EndpointEventBus(TypedDict, total=False):
    EventBusArn: NonPartnerEventBusArn


EndpointEventBusList = list[EndpointEventBus]


class ReplicationConfig(TypedDict, total=False):
    State: ReplicationState | None


class Secondary(TypedDict, total=False):
    Route: Route


class Primary(TypedDict, total=False):
    HealthCheck: HealthCheck


class FailoverConfig(TypedDict, total=False):
    Primary: Primary
    Secondary: Secondary


class RoutingConfig(TypedDict, total=False):
    FailoverConfig: FailoverConfig


class CreateEndpointRequest(ServiceRequest):
    Name: EndpointName
    Description: EndpointDescription | None
    RoutingConfig: RoutingConfig
    ReplicationConfig: ReplicationConfig | None
    EventBuses: EndpointEventBusList
    RoleArn: IamRoleArn | None


class CreateEndpointResponse(TypedDict, total=False):
    Name: EndpointName | None
    Arn: EndpointArn | None
    RoutingConfig: RoutingConfig | None
    ReplicationConfig: ReplicationConfig | None
    EventBuses: EndpointEventBusList | None
    RoleArn: IamRoleArn | None
    State: EndpointState | None


class Tag(TypedDict, total=False):
    Key: TagKey
    Value: TagValue


TagList = list[Tag]


class LogConfig(TypedDict, total=False):
    IncludeDetail: IncludeDetail | None
    Level: Level | None


class DeadLetterConfig(TypedDict, total=False):
    Arn: ResourceArn | None


class CreateEventBusRequest(ServiceRequest):
    Name: EventBusName
    EventSourceName: EventSourceName | None
    Description: EventBusDescription | None
    KmsKeyIdentifier: KmsKeyIdentifier | None
    DeadLetterConfig: DeadLetterConfig | None
    LogConfig: LogConfig | None
    Tags: TagList | None


class CreateEventBusResponse(TypedDict, total=False):
    EventBusArn: String | None
    Description: EventBusDescription | None
    KmsKeyIdentifier: KmsKeyIdentifier | None
    DeadLetterConfig: DeadLetterConfig | None
    LogConfig: LogConfig | None


class CreatePartnerEventSourceRequest(ServiceRequest):
    Name: EventSourceName
    Account: AccountId


class CreatePartnerEventSourceResponse(TypedDict, total=False):
    EventSourceArn: String | None


class DeactivateEventSourceRequest(ServiceRequest):
    Name: EventSourceName


class DeauthorizeConnectionRequest(ServiceRequest):
    Name: ConnectionName


class DeauthorizeConnectionResponse(TypedDict, total=False):
    ConnectionArn: ConnectionArn | None
    ConnectionState: ConnectionState | None
    CreationTime: Timestamp | None
    LastModifiedTime: Timestamp | None
    LastAuthorizedTime: Timestamp | None


class DeleteApiDestinationRequest(ServiceRequest):
    Name: ApiDestinationName


class DeleteApiDestinationResponse(TypedDict, total=False):
    pass


class DeleteArchiveRequest(ServiceRequest):
    ArchiveName: ArchiveName


class DeleteArchiveResponse(TypedDict, total=False):
    pass


class DeleteConnectionRequest(ServiceRequest):
    Name: ConnectionName


class DeleteConnectionResponse(TypedDict, total=False):
    ConnectionArn: ConnectionArn | None
    ConnectionState: ConnectionState | None
    CreationTime: Timestamp | None
    LastModifiedTime: Timestamp | None
    LastAuthorizedTime: Timestamp | None


class DeleteEndpointRequest(ServiceRequest):
    Name: EndpointName


class DeleteEndpointResponse(TypedDict, total=False):
    pass


class DeleteEventBusRequest(ServiceRequest):
    Name: EventBusName


class DeletePartnerEventSourceRequest(ServiceRequest):
    Name: EventSourceName
    Account: AccountId


class DeleteRuleRequest(ServiceRequest):
    Name: RuleName
    EventBusName: EventBusNameOrArn | None
    Force: Boolean | None


class DescribeApiDestinationRequest(ServiceRequest):
    Name: ApiDestinationName


class DescribeApiDestinationResponse(TypedDict, total=False):
    ApiDestinationArn: ApiDestinationArn | None
    Name: ApiDestinationName | None
    Description: ApiDestinationDescription | None
    ApiDestinationState: ApiDestinationState | None
    ConnectionArn: ConnectionArn | None
    InvocationEndpoint: HttpsEndpoint | None
    HttpMethod: ApiDestinationHttpMethod | None
    InvocationRateLimitPerSecond: ApiDestinationInvocationRateLimitPerSecond | None
    CreationTime: Timestamp | None
    LastModifiedTime: Timestamp | None


class DescribeArchiveRequest(ServiceRequest):
    ArchiveName: ArchiveName


class DescribeArchiveResponse(TypedDict, total=False):
    ArchiveArn: ArchiveArn | None
    ArchiveName: ArchiveName | None
    EventSourceArn: EventBusArn | None
    Description: ArchiveDescription | None
    EventPattern: EventPattern | None
    State: ArchiveState | None
    StateReason: ArchiveStateReason | None
    KmsKeyIdentifier: KmsKeyIdentifier | None
    RetentionDays: RetentionDays | None
    SizeBytes: Long | None
    EventCount: Long | None
    CreationTime: Timestamp | None


class DescribeConnectionRequest(ServiceRequest):
    Name: ConnectionName


class DescribeConnectionResponse(TypedDict, total=False):
    ConnectionArn: ConnectionArn | None
    Name: ConnectionName | None
    Description: ConnectionDescription | None
    InvocationConnectivityParameters: DescribeConnectionConnectivityParameters | None
    ConnectionState: ConnectionState | None
    StateReason: ConnectionStateReason | None
    AuthorizationType: ConnectionAuthorizationType | None
    SecretArn: SecretsManagerSecretArn | None
    KmsKeyIdentifier: KmsKeyIdentifier | None
    AuthParameters: ConnectionAuthResponseParameters | None
    CreationTime: Timestamp | None
    LastModifiedTime: Timestamp | None
    LastAuthorizedTime: Timestamp | None


class DescribeEndpointRequest(ServiceRequest):
    Name: EndpointName
    HomeRegion: HomeRegion | None


class DescribeEndpointResponse(TypedDict, total=False):
    Name: EndpointName | None
    Description: EndpointDescription | None
    Arn: EndpointArn | None
    RoutingConfig: RoutingConfig | None
    ReplicationConfig: ReplicationConfig | None
    EventBuses: EndpointEventBusList | None
    RoleArn: IamRoleArn | None
    EndpointId: EndpointId | None
    EndpointUrl: EndpointUrl | None
    State: EndpointState | None
    StateReason: EndpointStateReason | None
    CreationTime: Timestamp | None
    LastModifiedTime: Timestamp | None


class DescribeEventBusRequest(ServiceRequest):
    Name: EventBusNameOrArn | None


class DescribeEventBusResponse(TypedDict, total=False):
    Name: String | None
    Arn: String | None
    Description: EventBusDescription | None
    KmsKeyIdentifier: KmsKeyIdentifier | None
    DeadLetterConfig: DeadLetterConfig | None
    Policy: String | None
    LogConfig: LogConfig | None
    CreationTime: Timestamp | None
    LastModifiedTime: Timestamp | None


class DescribeEventSourceRequest(ServiceRequest):
    Name: EventSourceName


class DescribeEventSourceResponse(TypedDict, total=False):
    Arn: String | None
    CreatedBy: String | None
    CreationTime: Timestamp | None
    ExpirationTime: Timestamp | None
    Name: String | None
    State: EventSourceState | None


class DescribePartnerEventSourceRequest(ServiceRequest):
    Name: EventSourceName


class DescribePartnerEventSourceResponse(TypedDict, total=False):
    Arn: String | None
    Name: String | None


class DescribeReplayRequest(ServiceRequest):
    ReplayName: ReplayName


ReplayDestinationFilters = list[Arn]


class ReplayDestination(TypedDict, total=False):
    Arn: Arn
    FilterArns: ReplayDestinationFilters | None


class DescribeReplayResponse(TypedDict, total=False):
    ReplayName: ReplayName | None
    ReplayArn: ReplayArn | None
    Description: ReplayDescription | None
    State: ReplayState | None
    StateReason: ReplayStateReason | None
    EventSourceArn: ArchiveArn | None
    Destination: ReplayDestination | None
    EventStartTime: Timestamp | None
    EventEndTime: Timestamp | None
    EventLastReplayedTime: Timestamp | None
    ReplayStartTime: Timestamp | None
    ReplayEndTime: Timestamp | None


class DescribeRuleRequest(ServiceRequest):
    Name: RuleName
    EventBusName: EventBusNameOrArn | None


class DescribeRuleResponse(TypedDict, total=False):
    Name: RuleName | None
    Arn: RuleArn | None
    EventPattern: EventPattern | None
    ScheduleExpression: ScheduleExpression | None
    State: RuleState | None
    Description: RuleDescription | None
    RoleArn: RoleArn | None
    ManagedBy: ManagedBy | None
    EventBusName: EventBusName | None
    CreatedBy: CreatedBy | None


class DisableRuleRequest(ServiceRequest):
    Name: RuleName
    EventBusName: EventBusNameOrArn | None


class PlacementStrategy(TypedDict, total=False):
    type: PlacementStrategyType | None
    field: PlacementStrategyField | None


PlacementStrategies = list[PlacementStrategy]


class PlacementConstraint(TypedDict, total=False):
    type: PlacementConstraintType | None
    expression: PlacementConstraintExpression | None


PlacementConstraints = list[PlacementConstraint]


class NetworkConfiguration(TypedDict, total=False):
    awsvpcConfiguration: AwsVpcConfiguration | None


class EcsParameters(TypedDict, total=False):
    TaskDefinitionArn: Arn
    TaskCount: LimitMin1 | None
    LaunchType: LaunchType | None
    NetworkConfiguration: NetworkConfiguration | None
    PlatformVersion: String | None
    Group: String | None
    CapacityProviderStrategy: CapacityProviderStrategy | None
    EnableECSManagedTags: Boolean | None
    EnableExecuteCommand: Boolean | None
    PlacementConstraints: PlacementConstraints | None
    PlacementStrategy: PlacementStrategies | None
    PropagateTags: PropagateTags | None
    ReferenceId: ReferenceId | None
    Tags: TagList | None


class EnableRuleRequest(ServiceRequest):
    Name: RuleName
    EventBusName: EventBusNameOrArn | None


class Endpoint(TypedDict, total=False):
    Name: EndpointName | None
    Description: EndpointDescription | None
    Arn: EndpointArn | None
    RoutingConfig: RoutingConfig | None
    ReplicationConfig: ReplicationConfig | None
    EventBuses: EndpointEventBusList | None
    RoleArn: IamRoleArn | None
    EndpointId: EndpointId | None
    EndpointUrl: EndpointUrl | None
    State: EndpointState | None
    StateReason: EndpointStateReason | None
    CreationTime: Timestamp | None
    LastModifiedTime: Timestamp | None


EndpointList = list[Endpoint]


class EventBus(TypedDict, total=False):
    Name: String | None
    Arn: String | None
    Description: EventBusDescription | None
    Policy: String | None
    CreationTime: Timestamp | None
    LastModifiedTime: Timestamp | None


EventBusList = list[EventBus]
EventResourceList = list[EventResource]


class EventSource(TypedDict, total=False):
    Arn: String | None
    CreatedBy: String | None
    CreationTime: Timestamp | None
    ExpirationTime: Timestamp | None
    Name: String | None
    State: EventSourceState | None


EventSourceList = list[EventSource]
EventTime = datetime
HeaderParametersMap = dict[HeaderKey, HeaderValue]
QueryStringParametersMap = dict[QueryStringKey, QueryStringValue]
PathParameterList = list[PathParameter]


class HttpParameters(TypedDict, total=False):
    PathParameterValues: PathParameterList | None
    HeaderParameters: HeaderParametersMap | None
    QueryStringParameters: QueryStringParametersMap | None


TransformerPaths = dict[InputTransformerPathKey, TargetInputPath]


class InputTransformer(TypedDict, total=False):
    InputPathsMap: TransformerPaths | None
    InputTemplate: TransformerInput


class KinesisParameters(TypedDict, total=False):
    PartitionKeyPath: TargetPartitionKeyPath


class ListApiDestinationsRequest(ServiceRequest):
    NamePrefix: ApiDestinationName | None
    ConnectionArn: ConnectionArn | None
    NextToken: NextToken | None
    Limit: LimitMax100 | None


class ListApiDestinationsResponse(TypedDict, total=False):
    ApiDestinations: ApiDestinationResponseList | None
    NextToken: NextToken | None


class ListArchivesRequest(ServiceRequest):
    NamePrefix: ArchiveName | None
    EventSourceArn: EventBusArn | None
    State: ArchiveState | None
    NextToken: NextToken | None
    Limit: LimitMax100 | None


class ListArchivesResponse(TypedDict, total=False):
    Archives: ArchiveResponseList | None
    NextToken: NextToken | None


class ListConnectionsRequest(ServiceRequest):
    NamePrefix: ConnectionName | None
    ConnectionState: ConnectionState | None
    NextToken: NextToken | None
    Limit: LimitMax100 | None


class ListConnectionsResponse(TypedDict, total=False):
    Connections: ConnectionResponseList | None
    NextToken: NextToken | None


class ListEndpointsRequest(ServiceRequest):
    NamePrefix: EndpointName | None
    HomeRegion: HomeRegion | None
    NextToken: NextToken | None
    MaxResults: LimitMax100 | None


class ListEndpointsResponse(TypedDict, total=False):
    Endpoints: EndpointList | None
    NextToken: NextToken | None


class ListEventBusesRequest(ServiceRequest):
    NamePrefix: EventBusName | None
    NextToken: NextToken | None
    Limit: LimitMax100 | None


class ListEventBusesResponse(TypedDict, total=False):
    EventBuses: EventBusList | None
    NextToken: NextToken | None


class ListEventSourcesRequest(ServiceRequest):
    NamePrefix: EventSourceNamePrefix | None
    NextToken: NextToken | None
    Limit: LimitMax100 | None


class ListEventSourcesResponse(TypedDict, total=False):
    EventSources: EventSourceList | None
    NextToken: NextToken | None


class ListPartnerEventSourceAccountsRequest(ServiceRequest):
    EventSourceName: EventSourceName
    NextToken: NextToken | None
    Limit: LimitMax100 | None


class PartnerEventSourceAccount(TypedDict, total=False):
    Account: AccountId | None
    CreationTime: Timestamp | None
    ExpirationTime: Timestamp | None
    State: EventSourceState | None


PartnerEventSourceAccountList = list[PartnerEventSourceAccount]


class ListPartnerEventSourceAccountsResponse(TypedDict, total=False):
    PartnerEventSourceAccounts: PartnerEventSourceAccountList | None
    NextToken: NextToken | None


class ListPartnerEventSourcesRequest(ServiceRequest):
    NamePrefix: PartnerEventSourceNamePrefix
    NextToken: NextToken | None
    Limit: LimitMax100 | None


class PartnerEventSource(TypedDict, total=False):
    Arn: String | None
    Name: String | None


PartnerEventSourceList = list[PartnerEventSource]


class ListPartnerEventSourcesResponse(TypedDict, total=False):
    PartnerEventSources: PartnerEventSourceList | None
    NextToken: NextToken | None


class ListReplaysRequest(ServiceRequest):
    NamePrefix: ReplayName | None
    State: ReplayState | None
    EventSourceArn: ArchiveArn | None
    NextToken: NextToken | None
    Limit: LimitMax100 | None


class Replay(TypedDict, total=False):
    ReplayName: ReplayName | None
    EventSourceArn: ArchiveArn | None
    State: ReplayState | None
    StateReason: ReplayStateReason | None
    EventStartTime: Timestamp | None
    EventEndTime: Timestamp | None
    EventLastReplayedTime: Timestamp | None
    ReplayStartTime: Timestamp | None
    ReplayEndTime: Timestamp | None


ReplayList = list[Replay]


class ListReplaysResponse(TypedDict, total=False):
    Replays: ReplayList | None
    NextToken: NextToken | None


class ListRuleNamesByTargetRequest(ServiceRequest):
    TargetArn: TargetArn
    EventBusName: EventBusNameOrArn | None
    NextToken: NextToken | None
    Limit: LimitMax100 | None


RuleNameList = list[RuleName]


class ListRuleNamesByTargetResponse(TypedDict, total=False):
    RuleNames: RuleNameList | None
    NextToken: NextToken | None


class ListRulesRequest(ServiceRequest):
    NamePrefix: RuleName | None
    EventBusName: EventBusNameOrArn | None
    NextToken: NextToken | None
    Limit: LimitMax100 | None


class Rule(TypedDict, total=False):
    Name: RuleName | None
    Arn: RuleArn | None
    EventPattern: EventPattern | None
    State: RuleState | None
    Description: RuleDescription | None
    ScheduleExpression: ScheduleExpression | None
    RoleArn: RoleArn | None
    ManagedBy: ManagedBy | None
    EventBusName: EventBusName | None


RuleResponseList = list[Rule]


class ListRulesResponse(TypedDict, total=False):
    Rules: RuleResponseList | None
    NextToken: NextToken | None


class ListTagsForResourceRequest(ServiceRequest):
    ResourceARN: Arn


class ListTagsForResourceResponse(TypedDict, total=False):
    Tags: TagList | None


class ListTargetsByRuleRequest(ServiceRequest):
    Rule: RuleName
    EventBusName: EventBusNameOrArn | None
    NextToken: NextToken | None
    Limit: LimitMax100 | None


class RetryPolicy(TypedDict, total=False):
    MaximumRetryAttempts: MaximumRetryAttempts | None
    MaximumEventAgeInSeconds: MaximumEventAgeInSeconds | None


class SageMakerPipelineParameter(TypedDict, total=False):
    Name: SageMakerPipelineParameterName
    Value: SageMakerPipelineParameterValue


SageMakerPipelineParameterList = list[SageMakerPipelineParameter]


class SageMakerPipelineParameters(TypedDict, total=False):
    PipelineParameterList: SageMakerPipelineParameterList | None


Sqls = list[Sql]


class RedshiftDataParameters(TypedDict, total=False):
    SecretManagerArn: RedshiftSecretManagerArn | None
    Database: Database
    DbUser: DbUser | None
    Sql: Sql | None
    StatementName: StatementName | None
    WithEvent: Boolean | None
    Sqls: Sqls | None


class SqsParameters(TypedDict, total=False):
    MessageGroupId: MessageGroupId | None


RunCommandTargetValues = list[RunCommandTargetValue]


class RunCommandTarget(TypedDict, total=False):
    Key: RunCommandTargetKey
    Values: RunCommandTargetValues


RunCommandTargets = list[RunCommandTarget]


class RunCommandParameters(TypedDict, total=False):
    RunCommandTargets: RunCommandTargets


class Target(TypedDict, total=False):
    Id: TargetId
    Arn: TargetArn
    RoleArn: RoleArn | None
    Input: TargetInput | None
    InputPath: TargetInputPath | None
    InputTransformer: InputTransformer | None
    KinesisParameters: KinesisParameters | None
    RunCommandParameters: RunCommandParameters | None
    EcsParameters: EcsParameters | None
    BatchParameters: BatchParameters | None
    SqsParameters: SqsParameters | None
    HttpParameters: HttpParameters | None
    RedshiftDataParameters: RedshiftDataParameters | None
    SageMakerPipelineParameters: SageMakerPipelineParameters | None
    DeadLetterConfig: DeadLetterConfig | None
    RetryPolicy: RetryPolicy | None
    AppSyncParameters: AppSyncParameters | None


TargetList = list[Target]


class ListTargetsByRuleResponse(TypedDict, total=False):
    Targets: TargetList | None
    NextToken: NextToken | None


class PutEventsRequestEntry(TypedDict, total=False):
    Time: EventTime | None
    Source: String | None
    Resources: EventResourceList | None
    DetailType: String | None
    Detail: String | None
    EventBusName: NonPartnerEventBusNameOrArn | None
    TraceHeader: TraceHeader | None


PutEventsRequestEntryList = list[PutEventsRequestEntry]


class PutEventsRequest(ServiceRequest):
    Entries: PutEventsRequestEntryList
    EndpointId: EndpointId | None


class PutEventsResultEntry(TypedDict, total=False):
    EventId: EventId | None
    ErrorCode: ErrorCode | None
    ErrorMessage: ErrorMessage | None


PutEventsResultEntryList = list[PutEventsResultEntry]


class PutEventsResponse(TypedDict, total=False):
    FailedEntryCount: Integer | None
    Entries: PutEventsResultEntryList | None


class PutPartnerEventsRequestEntry(TypedDict, total=False):
    Time: EventTime | None
    Source: EventSourceName | None
    Resources: EventResourceList | None
    DetailType: String | None
    Detail: String | None


PutPartnerEventsRequestEntryList = list[PutPartnerEventsRequestEntry]


class PutPartnerEventsRequest(ServiceRequest):
    Entries: PutPartnerEventsRequestEntryList


class PutPartnerEventsResultEntry(TypedDict, total=False):
    EventId: EventId | None
    ErrorCode: ErrorCode | None
    ErrorMessage: ErrorMessage | None


PutPartnerEventsResultEntryList = list[PutPartnerEventsResultEntry]


class PutPartnerEventsResponse(TypedDict, total=False):
    FailedEntryCount: Integer | None
    Entries: PutPartnerEventsResultEntryList | None


class PutPermissionRequest(ServiceRequest):
    EventBusName: NonPartnerEventBusName | None
    Action: Action | None
    Principal: Principal | None
    StatementId: StatementId | None
    Condition: Condition | None
    Policy: String | None


class PutRuleRequest(ServiceRequest):
    Name: RuleName
    ScheduleExpression: ScheduleExpression | None
    EventPattern: EventPattern | None
    State: RuleState | None
    Description: RuleDescription | None
    RoleArn: RoleArn | None
    Tags: TagList | None
    EventBusName: EventBusNameOrArn | None


class PutRuleResponse(TypedDict, total=False):
    RuleArn: RuleArn | None


class PutTargetsRequest(ServiceRequest):
    Rule: RuleName
    EventBusName: EventBusNameOrArn | None
    Targets: TargetList


class PutTargetsResultEntry(TypedDict, total=False):
    TargetId: TargetId | None
    ErrorCode: ErrorCode | None
    ErrorMessage: ErrorMessage | None


PutTargetsResultEntryList = list[PutTargetsResultEntry]


class PutTargetsResponse(TypedDict, total=False):
    FailedEntryCount: Integer | None
    FailedEntries: PutTargetsResultEntryList | None


class RemovePermissionRequest(ServiceRequest):
    StatementId: StatementId | None
    RemoveAllPermissions: Boolean | None
    EventBusName: NonPartnerEventBusName | None


TargetIdList = list[TargetId]


class RemoveTargetsRequest(ServiceRequest):
    Rule: RuleName
    EventBusName: EventBusNameOrArn | None
    Ids: TargetIdList
    Force: Boolean | None


class RemoveTargetsResultEntry(TypedDict, total=False):
    TargetId: TargetId | None
    ErrorCode: ErrorCode | None
    ErrorMessage: ErrorMessage | None


RemoveTargetsResultEntryList = list[RemoveTargetsResultEntry]


class RemoveTargetsResponse(TypedDict, total=False):
    FailedEntryCount: Integer | None
    FailedEntries: RemoveTargetsResultEntryList | None


class StartReplayRequest(ServiceRequest):
    ReplayName: ReplayName
    Description: ReplayDescription | None
    EventSourceArn: ArchiveArn
    EventStartTime: Timestamp
    EventEndTime: Timestamp
    Destination: ReplayDestination


class StartReplayResponse(TypedDict, total=False):
    ReplayArn: ReplayArn | None
    State: ReplayState | None
    StateReason: ReplayStateReason | None
    ReplayStartTime: Timestamp | None


TagKeyList = list[TagKey]


class TagResourceRequest(ServiceRequest):
    ResourceARN: Arn
    Tags: TagList


class TagResourceResponse(TypedDict, total=False):
    pass


class TestEventPatternRequest(ServiceRequest):
    EventPattern: EventPattern
    Event: String


class TestEventPatternResponse(TypedDict, total=False):
    Result: Boolean | None


class UntagResourceRequest(ServiceRequest):
    ResourceARN: Arn
    TagKeys: TagKeyList


class UntagResourceResponse(TypedDict, total=False):
    pass


class UpdateApiDestinationRequest(ServiceRequest):
    Name: ApiDestinationName
    Description: ApiDestinationDescription | None
    ConnectionArn: ConnectionArn | None
    InvocationEndpoint: HttpsEndpoint | None
    HttpMethod: ApiDestinationHttpMethod | None
    InvocationRateLimitPerSecond: ApiDestinationInvocationRateLimitPerSecond | None


class UpdateApiDestinationResponse(TypedDict, total=False):
    ApiDestinationArn: ApiDestinationArn | None
    ApiDestinationState: ApiDestinationState | None
    CreationTime: Timestamp | None
    LastModifiedTime: Timestamp | None


class UpdateArchiveRequest(ServiceRequest):
    ArchiveName: ArchiveName
    Description: ArchiveDescription | None
    EventPattern: EventPattern | None
    RetentionDays: RetentionDays | None
    KmsKeyIdentifier: KmsKeyIdentifier | None


class UpdateArchiveResponse(TypedDict, total=False):
    ArchiveArn: ArchiveArn | None
    State: ArchiveState | None
    StateReason: ArchiveStateReason | None
    CreationTime: Timestamp | None


class UpdateConnectionApiKeyAuthRequestParameters(TypedDict, total=False):
    ApiKeyName: AuthHeaderParameters | None
    ApiKeyValue: AuthHeaderParametersSensitive | None


class UpdateConnectionOAuthClientRequestParameters(TypedDict, total=False):
    ClientID: AuthHeaderParameters | None
    ClientSecret: AuthHeaderParametersSensitive | None


class UpdateConnectionOAuthRequestParameters(TypedDict, total=False):
    ClientParameters: UpdateConnectionOAuthClientRequestParameters | None
    AuthorizationEndpoint: HttpsEndpoint | None
    HttpMethod: ConnectionOAuthHttpMethod | None
    OAuthHttpParameters: ConnectionHttpParameters | None


class UpdateConnectionBasicAuthRequestParameters(TypedDict, total=False):
    Username: AuthHeaderParameters | None
    Password: AuthHeaderParametersSensitive | None


class UpdateConnectionAuthRequestParameters(TypedDict, total=False):
    BasicAuthParameters: UpdateConnectionBasicAuthRequestParameters | None
    OAuthParameters: UpdateConnectionOAuthRequestParameters | None
    ApiKeyAuthParameters: UpdateConnectionApiKeyAuthRequestParameters | None
    InvocationHttpParameters: ConnectionHttpParameters | None
    ConnectivityParameters: ConnectivityResourceParameters | None


class UpdateConnectionRequest(ServiceRequest):
    Name: ConnectionName
    Description: ConnectionDescription | None
    AuthorizationType: ConnectionAuthorizationType | None
    AuthParameters: UpdateConnectionAuthRequestParameters | None
    InvocationConnectivityParameters: ConnectivityResourceParameters | None
    KmsKeyIdentifier: KmsKeyIdentifier | None


class UpdateConnectionResponse(TypedDict, total=False):
    ConnectionArn: ConnectionArn | None
    ConnectionState: ConnectionState | None
    CreationTime: Timestamp | None
    LastModifiedTime: Timestamp | None
    LastAuthorizedTime: Timestamp | None


class UpdateEndpointRequest(ServiceRequest):
    Name: EndpointName
    Description: EndpointDescription | None
    RoutingConfig: RoutingConfig | None
    ReplicationConfig: ReplicationConfig | None
    EventBuses: EndpointEventBusList | None
    RoleArn: IamRoleArn | None


class UpdateEndpointResponse(TypedDict, total=False):
    Name: EndpointName | None
    Arn: EndpointArn | None
    RoutingConfig: RoutingConfig | None
    ReplicationConfig: ReplicationConfig | None
    EventBuses: EndpointEventBusList | None
    RoleArn: IamRoleArn | None
    EndpointId: EndpointId | None
    EndpointUrl: EndpointUrl | None
    State: EndpointState | None


class UpdateEventBusRequest(ServiceRequest):
    Name: EventBusName | None
    KmsKeyIdentifier: KmsKeyIdentifier | None
    Description: EventBusDescription | None
    DeadLetterConfig: DeadLetterConfig | None
    LogConfig: LogConfig | None


class UpdateEventBusResponse(TypedDict, total=False):
    Arn: String | None
    Name: EventBusName | None
    KmsKeyIdentifier: KmsKeyIdentifier | None
    Description: EventBusDescription | None
    DeadLetterConfig: DeadLetterConfig | None
    LogConfig: LogConfig | None


class EventsApi:
    service: str = "events"
    version: str = "2015-10-07"

    @handler("ActivateEventSource")
    def activate_event_source(
        self, context: RequestContext, name: EventSourceName, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("CancelReplay")
    def cancel_replay(
        self, context: RequestContext, replay_name: ReplayName, **kwargs
    ) -> CancelReplayResponse:
        raise NotImplementedError

    @handler("CreateApiDestination")
    def create_api_destination(
        self,
        context: RequestContext,
        name: ApiDestinationName,
        connection_arn: ConnectionArn,
        invocation_endpoint: HttpsEndpoint,
        http_method: ApiDestinationHttpMethod,
        description: ApiDestinationDescription | None = None,
        invocation_rate_limit_per_second: ApiDestinationInvocationRateLimitPerSecond | None = None,
        **kwargs,
    ) -> CreateApiDestinationResponse:
        raise NotImplementedError

    @handler("CreateArchive")
    def create_archive(
        self,
        context: RequestContext,
        archive_name: ArchiveName,
        event_source_arn: EventBusArn,
        description: ArchiveDescription | None = None,
        event_pattern: EventPattern | None = None,
        retention_days: RetentionDays | None = None,
        kms_key_identifier: KmsKeyIdentifier | None = None,
        **kwargs,
    ) -> CreateArchiveResponse:
        raise NotImplementedError

    @handler("CreateConnection")
    def create_connection(
        self,
        context: RequestContext,
        name: ConnectionName,
        authorization_type: ConnectionAuthorizationType,
        auth_parameters: CreateConnectionAuthRequestParameters,
        description: ConnectionDescription | None = None,
        invocation_connectivity_parameters: ConnectivityResourceParameters | None = None,
        kms_key_identifier: KmsKeyIdentifier | None = None,
        **kwargs,
    ) -> CreateConnectionResponse:
        raise NotImplementedError

    @handler("CreateEndpoint")
    def create_endpoint(
        self,
        context: RequestContext,
        name: EndpointName,
        routing_config: RoutingConfig,
        event_buses: EndpointEventBusList,
        description: EndpointDescription | None = None,
        replication_config: ReplicationConfig | None = None,
        role_arn: IamRoleArn | None = None,
        **kwargs,
    ) -> CreateEndpointResponse:
        raise NotImplementedError

    @handler("CreateEventBus")
    def create_event_bus(
        self,
        context: RequestContext,
        name: EventBusName,
        event_source_name: EventSourceName | None = None,
        description: EventBusDescription | None = None,
        kms_key_identifier: KmsKeyIdentifier | None = None,
        dead_letter_config: DeadLetterConfig | None = None,
        log_config: LogConfig | None = None,
        tags: TagList | None = None,
        **kwargs,
    ) -> CreateEventBusResponse:
        raise NotImplementedError

    @handler("CreatePartnerEventSource")
    def create_partner_event_source(
        self, context: RequestContext, name: EventSourceName, account: AccountId, **kwargs
    ) -> CreatePartnerEventSourceResponse:
        raise NotImplementedError

    @handler("DeactivateEventSource")
    def deactivate_event_source(
        self, context: RequestContext, name: EventSourceName, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("DeauthorizeConnection")
    def deauthorize_connection(
        self, context: RequestContext, name: ConnectionName, **kwargs
    ) -> DeauthorizeConnectionResponse:
        raise NotImplementedError

    @handler("DeleteApiDestination")
    def delete_api_destination(
        self, context: RequestContext, name: ApiDestinationName, **kwargs
    ) -> DeleteApiDestinationResponse:
        raise NotImplementedError

    @handler("DeleteArchive")
    def delete_archive(
        self, context: RequestContext, archive_name: ArchiveName, **kwargs
    ) -> DeleteArchiveResponse:
        raise NotImplementedError

    @handler("DeleteConnection")
    def delete_connection(
        self, context: RequestContext, name: ConnectionName, **kwargs
    ) -> DeleteConnectionResponse:
        raise NotImplementedError

    @handler("DeleteEndpoint")
    def delete_endpoint(
        self, context: RequestContext, name: EndpointName, **kwargs
    ) -> DeleteEndpointResponse:
        raise NotImplementedError

    @handler("DeleteEventBus")
    def delete_event_bus(self, context: RequestContext, name: EventBusName, **kwargs) -> None:
        raise NotImplementedError

    @handler("DeletePartnerEventSource")
    def delete_partner_event_source(
        self, context: RequestContext, name: EventSourceName, account: AccountId, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("DeleteRule")
    def delete_rule(
        self,
        context: RequestContext,
        name: RuleName,
        event_bus_name: EventBusNameOrArn | None = None,
        force: Boolean | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("DescribeApiDestination")
    def describe_api_destination(
        self, context: RequestContext, name: ApiDestinationName, **kwargs
    ) -> DescribeApiDestinationResponse:
        raise NotImplementedError

    @handler("DescribeArchive")
    def describe_archive(
        self, context: RequestContext, archive_name: ArchiveName, **kwargs
    ) -> DescribeArchiveResponse:
        raise NotImplementedError

    @handler("DescribeConnection")
    def describe_connection(
        self, context: RequestContext, name: ConnectionName, **kwargs
    ) -> DescribeConnectionResponse:
        raise NotImplementedError

    @handler("DescribeEndpoint")
    def describe_endpoint(
        self,
        context: RequestContext,
        name: EndpointName,
        home_region: HomeRegion | None = None,
        **kwargs,
    ) -> DescribeEndpointResponse:
        raise NotImplementedError

    @handler("DescribeEventBus")
    def describe_event_bus(
        self, context: RequestContext, name: EventBusNameOrArn | None = None, **kwargs
    ) -> DescribeEventBusResponse:
        raise NotImplementedError

    @handler("DescribeEventSource")
    def describe_event_source(
        self, context: RequestContext, name: EventSourceName, **kwargs
    ) -> DescribeEventSourceResponse:
        raise NotImplementedError

    @handler("DescribePartnerEventSource")
    def describe_partner_event_source(
        self, context: RequestContext, name: EventSourceName, **kwargs
    ) -> DescribePartnerEventSourceResponse:
        raise NotImplementedError

    @handler("DescribeReplay")
    def describe_replay(
        self, context: RequestContext, replay_name: ReplayName, **kwargs
    ) -> DescribeReplayResponse:
        raise NotImplementedError

    @handler("DescribeRule")
    def describe_rule(
        self,
        context: RequestContext,
        name: RuleName,
        event_bus_name: EventBusNameOrArn | None = None,
        **kwargs,
    ) -> DescribeRuleResponse:
        raise NotImplementedError

    @handler("DisableRule")
    def disable_rule(
        self,
        context: RequestContext,
        name: RuleName,
        event_bus_name: EventBusNameOrArn | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("EnableRule")
    def enable_rule(
        self,
        context: RequestContext,
        name: RuleName,
        event_bus_name: EventBusNameOrArn | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("ListApiDestinations")
    def list_api_destinations(
        self,
        context: RequestContext,
        name_prefix: ApiDestinationName | None = None,
        connection_arn: ConnectionArn | None = None,
        next_token: NextToken | None = None,
        limit: LimitMax100 | None = None,
        **kwargs,
    ) -> ListApiDestinationsResponse:
        raise NotImplementedError

    @handler("ListArchives")
    def list_archives(
        self,
        context: RequestContext,
        name_prefix: ArchiveName | None = None,
        event_source_arn: EventBusArn | None = None,
        state: ArchiveState | None = None,
        next_token: NextToken | None = None,
        limit: LimitMax100 | None = None,
        **kwargs,
    ) -> ListArchivesResponse:
        raise NotImplementedError

    @handler("ListConnections")
    def list_connections(
        self,
        context: RequestContext,
        name_prefix: ConnectionName | None = None,
        connection_state: ConnectionState | None = None,
        next_token: NextToken | None = None,
        limit: LimitMax100 | None = None,
        **kwargs,
    ) -> ListConnectionsResponse:
        raise NotImplementedError

    @handler("ListEndpoints")
    def list_endpoints(
        self,
        context: RequestContext,
        name_prefix: EndpointName | None = None,
        home_region: HomeRegion | None = None,
        next_token: NextToken | None = None,
        max_results: LimitMax100 | None = None,
        **kwargs,
    ) -> ListEndpointsResponse:
        raise NotImplementedError

    @handler("ListEventBuses")
    def list_event_buses(
        self,
        context: RequestContext,
        name_prefix: EventBusName | None = None,
        next_token: NextToken | None = None,
        limit: LimitMax100 | None = None,
        **kwargs,
    ) -> ListEventBusesResponse:
        raise NotImplementedError

    @handler("ListEventSources")
    def list_event_sources(
        self,
        context: RequestContext,
        name_prefix: EventSourceNamePrefix | None = None,
        next_token: NextToken | None = None,
        limit: LimitMax100 | None = None,
        **kwargs,
    ) -> ListEventSourcesResponse:
        raise NotImplementedError

    @handler("ListPartnerEventSourceAccounts")
    def list_partner_event_source_accounts(
        self,
        context: RequestContext,
        event_source_name: EventSourceName,
        next_token: NextToken | None = None,
        limit: LimitMax100 | None = None,
        **kwargs,
    ) -> ListPartnerEventSourceAccountsResponse:
        raise NotImplementedError

    @handler("ListPartnerEventSources")
    def list_partner_event_sources(
        self,
        context: RequestContext,
        name_prefix: PartnerEventSourceNamePrefix,
        next_token: NextToken | None = None,
        limit: LimitMax100 | None = None,
        **kwargs,
    ) -> ListPartnerEventSourcesResponse:
        raise NotImplementedError

    @handler("ListReplays")
    def list_replays(
        self,
        context: RequestContext,
        name_prefix: ReplayName | None = None,
        state: ReplayState | None = None,
        event_source_arn: ArchiveArn | None = None,
        next_token: NextToken | None = None,
        limit: LimitMax100 | None = None,
        **kwargs,
    ) -> ListReplaysResponse:
        raise NotImplementedError

    @handler("ListRuleNamesByTarget")
    def list_rule_names_by_target(
        self,
        context: RequestContext,
        target_arn: TargetArn,
        event_bus_name: EventBusNameOrArn | None = None,
        next_token: NextToken | None = None,
        limit: LimitMax100 | None = None,
        **kwargs,
    ) -> ListRuleNamesByTargetResponse:
        raise NotImplementedError

    @handler("ListRules")
    def list_rules(
        self,
        context: RequestContext,
        name_prefix: RuleName | None = None,
        event_bus_name: EventBusNameOrArn | None = None,
        next_token: NextToken | None = None,
        limit: LimitMax100 | None = None,
        **kwargs,
    ) -> ListRulesResponse:
        raise NotImplementedError

    @handler("ListTagsForResource")
    def list_tags_for_resource(
        self, context: RequestContext, resource_arn: Arn, **kwargs
    ) -> ListTagsForResourceResponse:
        raise NotImplementedError

    @handler("ListTargetsByRule")
    def list_targets_by_rule(
        self,
        context: RequestContext,
        rule: RuleName,
        event_bus_name: EventBusNameOrArn | None = None,
        next_token: NextToken | None = None,
        limit: LimitMax100 | None = None,
        **kwargs,
    ) -> ListTargetsByRuleResponse:
        raise NotImplementedError

    @handler("PutEvents")
    def put_events(
        self,
        context: RequestContext,
        entries: PutEventsRequestEntryList,
        endpoint_id: EndpointId | None = None,
        **kwargs,
    ) -> PutEventsResponse:
        raise NotImplementedError

    @handler("PutPartnerEvents")
    def put_partner_events(
        self, context: RequestContext, entries: PutPartnerEventsRequestEntryList, **kwargs
    ) -> PutPartnerEventsResponse:
        raise NotImplementedError

    @handler("PutPermission")
    def put_permission(
        self,
        context: RequestContext,
        event_bus_name: NonPartnerEventBusName | None = None,
        action: Action | None = None,
        principal: Principal | None = None,
        statement_id: StatementId | None = None,
        condition: Condition | None = None,
        policy: String | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("PutRule")
    def put_rule(
        self,
        context: RequestContext,
        name: RuleName,
        schedule_expression: ScheduleExpression | None = None,
        event_pattern: EventPattern | None = None,
        state: RuleState | None = None,
        description: RuleDescription | None = None,
        role_arn: RoleArn | None = None,
        tags: TagList | None = None,
        event_bus_name: EventBusNameOrArn | None = None,
        **kwargs,
    ) -> PutRuleResponse:
        raise NotImplementedError

    @handler("PutTargets")
    def put_targets(
        self,
        context: RequestContext,
        rule: RuleName,
        targets: TargetList,
        event_bus_name: EventBusNameOrArn | None = None,
        **kwargs,
    ) -> PutTargetsResponse:
        raise NotImplementedError

    @handler("RemovePermission")
    def remove_permission(
        self,
        context: RequestContext,
        statement_id: StatementId | None = None,
        remove_all_permissions: Boolean | None = None,
        event_bus_name: NonPartnerEventBusName | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("RemoveTargets")
    def remove_targets(
        self,
        context: RequestContext,
        rule: RuleName,
        ids: TargetIdList,
        event_bus_name: EventBusNameOrArn | None = None,
        force: Boolean | None = None,
        **kwargs,
    ) -> RemoveTargetsResponse:
        raise NotImplementedError

    @handler("StartReplay")
    def start_replay(
        self,
        context: RequestContext,
        replay_name: ReplayName,
        event_source_arn: ArchiveArn,
        event_start_time: Timestamp,
        event_end_time: Timestamp,
        destination: ReplayDestination,
        description: ReplayDescription | None = None,
        **kwargs,
    ) -> StartReplayResponse:
        raise NotImplementedError

    @handler("TagResource")
    def tag_resource(
        self, context: RequestContext, resource_arn: Arn, tags: TagList, **kwargs
    ) -> TagResourceResponse:
        raise NotImplementedError

    @handler("TestEventPattern")
    def test_event_pattern(
        self, context: RequestContext, event_pattern: EventPattern, event: String, **kwargs
    ) -> TestEventPatternResponse:
        raise NotImplementedError

    @handler("UntagResource")
    def untag_resource(
        self, context: RequestContext, resource_arn: Arn, tag_keys: TagKeyList, **kwargs
    ) -> UntagResourceResponse:
        raise NotImplementedError

    @handler("UpdateApiDestination")
    def update_api_destination(
        self,
        context: RequestContext,
        name: ApiDestinationName,
        description: ApiDestinationDescription | None = None,
        connection_arn: ConnectionArn | None = None,
        invocation_endpoint: HttpsEndpoint | None = None,
        http_method: ApiDestinationHttpMethod | None = None,
        invocation_rate_limit_per_second: ApiDestinationInvocationRateLimitPerSecond | None = None,
        **kwargs,
    ) -> UpdateApiDestinationResponse:
        raise NotImplementedError

    @handler("UpdateArchive")
    def update_archive(
        self,
        context: RequestContext,
        archive_name: ArchiveName,
        description: ArchiveDescription | None = None,
        event_pattern: EventPattern | None = None,
        retention_days: RetentionDays | None = None,
        kms_key_identifier: KmsKeyIdentifier | None = None,
        **kwargs,
    ) -> UpdateArchiveResponse:
        raise NotImplementedError

    @handler("UpdateConnection")
    def update_connection(
        self,
        context: RequestContext,
        name: ConnectionName,
        description: ConnectionDescription | None = None,
        authorization_type: ConnectionAuthorizationType | None = None,
        auth_parameters: UpdateConnectionAuthRequestParameters | None = None,
        invocation_connectivity_parameters: ConnectivityResourceParameters | None = None,
        kms_key_identifier: KmsKeyIdentifier | None = None,
        **kwargs,
    ) -> UpdateConnectionResponse:
        raise NotImplementedError

    @handler("UpdateEndpoint")
    def update_endpoint(
        self,
        context: RequestContext,
        name: EndpointName,
        description: EndpointDescription | None = None,
        routing_config: RoutingConfig | None = None,
        replication_config: ReplicationConfig | None = None,
        event_buses: EndpointEventBusList | None = None,
        role_arn: IamRoleArn | None = None,
        **kwargs,
    ) -> UpdateEndpointResponse:
        raise NotImplementedError

    @handler("UpdateEventBus")
    def update_event_bus(
        self,
        context: RequestContext,
        name: EventBusName | None = None,
        kms_key_identifier: KmsKeyIdentifier | None = None,
        description: EventBusDescription | None = None,
        dead_letter_config: DeadLetterConfig | None = None,
        log_config: LogConfig | None = None,
        **kwargs,
    ) -> UpdateEventBusResponse:
        raise NotImplementedError
