import sys
from datetime import datetime
from typing import Dict, List, Optional

if sys.version_info >= (3, 8):
    from typing import TypedDict
else:
    from typing_extensions import TypedDict

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
EventBusName = str
EventBusNameOrArn = str
EventId = str
EventPattern = str
EventResource = str
EventSourceName = str
EventSourceNamePrefix = str
HeaderKey = str
HeaderValue = str
HealthCheck = str
HomeRegion = str
HttpsEndpoint = str
IamRoleArn = str
InputTransformerPathKey = str
Integer = int
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
RedshiftSecretManagerArn = str
ReferenceId = str
ReplayArn = str
ReplayDescription = str
ReplayName = str
ReplayStateReason = str
ResourceArn = str
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


class ApiDestinationHttpMethod(str):
    POST = "POST"
    GET = "GET"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"


class ApiDestinationState(str):
    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"


class ArchiveState(str):
    ENABLED = "ENABLED"
    DISABLED = "DISABLED"
    CREATING = "CREATING"
    UPDATING = "UPDATING"
    CREATE_FAILED = "CREATE_FAILED"
    UPDATE_FAILED = "UPDATE_FAILED"


class AssignPublicIp(str):
    ENABLED = "ENABLED"
    DISABLED = "DISABLED"


class ConnectionAuthorizationType(str):
    BASIC = "BASIC"
    OAUTH_CLIENT_CREDENTIALS = "OAUTH_CLIENT_CREDENTIALS"
    API_KEY = "API_KEY"


class ConnectionOAuthHttpMethod(str):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"


class ConnectionState(str):
    CREATING = "CREATING"
    UPDATING = "UPDATING"
    DELETING = "DELETING"
    AUTHORIZED = "AUTHORIZED"
    DEAUTHORIZED = "DEAUTHORIZED"
    AUTHORIZING = "AUTHORIZING"
    DEAUTHORIZING = "DEAUTHORIZING"


class EndpointState(str):
    ACTIVE = "ACTIVE"
    CREATING = "CREATING"
    UPDATING = "UPDATING"
    DELETING = "DELETING"
    CREATE_FAILED = "CREATE_FAILED"
    UPDATE_FAILED = "UPDATE_FAILED"
    DELETE_FAILED = "DELETE_FAILED"


class EventSourceState(str):
    PENDING = "PENDING"
    ACTIVE = "ACTIVE"
    DELETED = "DELETED"


class LaunchType(str):
    EC2 = "EC2"
    FARGATE = "FARGATE"
    EXTERNAL = "EXTERNAL"


class PlacementConstraintType(str):
    distinctInstance = "distinctInstance"
    memberOf = "memberOf"


class PlacementStrategyType(str):
    random = "random"
    spread = "spread"
    binpack = "binpack"


class PropagateTags(str):
    TASK_DEFINITION = "TASK_DEFINITION"


class ReplayState(str):
    STARTING = "STARTING"
    RUNNING = "RUNNING"
    CANCELLING = "CANCELLING"
    COMPLETED = "COMPLETED"
    CANCELLED = "CANCELLED"
    FAILED = "FAILED"


class ReplicationState(str):
    ENABLED = "ENABLED"
    DISABLED = "DISABLED"


class RuleState(str):
    ENABLED = "ENABLED"
    DISABLED = "DISABLED"


class ConcurrentModificationException(ServiceException):
    pass


class IllegalStatusException(ServiceException):
    pass


class InternalException(ServiceException):
    pass


class InvalidEventPatternException(ServiceException):
    pass


class InvalidStateException(ServiceException):
    pass


class LimitExceededException(ServiceException):
    pass


class ManagedRuleException(ServiceException):
    pass


class OperationDisabledException(ServiceException):
    pass


class PolicyLengthExceededException(ServiceException):
    pass


class ResourceAlreadyExistsException(ServiceException):
    pass


class ResourceNotFoundException(ServiceException):
    pass


class ActivateEventSourceRequest(ServiceRequest):
    Name: EventSourceName


Timestamp = datetime


class ApiDestination(TypedDict, total=False):
    ApiDestinationArn: Optional[ApiDestinationArn]
    Name: Optional[ApiDestinationName]
    ApiDestinationState: Optional[ApiDestinationState]
    ConnectionArn: Optional[ConnectionArn]
    InvocationEndpoint: Optional[HttpsEndpoint]
    HttpMethod: Optional[ApiDestinationHttpMethod]
    InvocationRateLimitPerSecond: Optional[ApiDestinationInvocationRateLimitPerSecond]
    CreationTime: Optional[Timestamp]
    LastModifiedTime: Optional[Timestamp]


ApiDestinationResponseList = List[ApiDestination]
Long = int


class Archive(TypedDict, total=False):
    ArchiveName: Optional[ArchiveName]
    EventSourceArn: Optional[Arn]
    State: Optional[ArchiveState]
    StateReason: Optional[ArchiveStateReason]
    RetentionDays: Optional[RetentionDays]
    SizeBytes: Optional[Long]
    EventCount: Optional[Long]
    CreationTime: Optional[Timestamp]


ArchiveResponseList = List[Archive]
StringList = List[String]


class AwsVpcConfiguration(TypedDict, total=False):
    Subnets: StringList
    SecurityGroups: Optional[StringList]
    AssignPublicIp: Optional[AssignPublicIp]


class BatchArrayProperties(TypedDict, total=False):
    Size: Optional[Integer]


class BatchRetryStrategy(TypedDict, total=False):
    Attempts: Optional[Integer]


class BatchParameters(TypedDict, total=False):
    JobDefinition: String
    JobName: String
    ArrayProperties: Optional[BatchArrayProperties]
    RetryStrategy: Optional[BatchRetryStrategy]


class CancelReplayRequest(ServiceRequest):
    ReplayName: ReplayName


class CancelReplayResponse(TypedDict, total=False):
    ReplayArn: Optional[ReplayArn]
    State: Optional[ReplayState]
    StateReason: Optional[ReplayStateReason]


class CapacityProviderStrategyItem(TypedDict, total=False):
    capacityProvider: CapacityProvider
    weight: Optional[CapacityProviderStrategyItemWeight]
    base: Optional[CapacityProviderStrategyItemBase]


CapacityProviderStrategy = List[CapacityProviderStrategyItem]


class Condition(TypedDict, total=False):
    Type: String
    Key: String
    Value: String


class Connection(TypedDict, total=False):
    ConnectionArn: Optional[ConnectionArn]
    Name: Optional[ConnectionName]
    ConnectionState: Optional[ConnectionState]
    StateReason: Optional[ConnectionStateReason]
    AuthorizationType: Optional[ConnectionAuthorizationType]
    CreationTime: Optional[Timestamp]
    LastModifiedTime: Optional[Timestamp]
    LastAuthorizedTime: Optional[Timestamp]


class ConnectionApiKeyAuthResponseParameters(TypedDict, total=False):
    ApiKeyName: Optional[AuthHeaderParameters]


class ConnectionBodyParameter(TypedDict, total=False):
    Key: Optional[String]
    Value: Optional[String]
    IsValueSecret: Optional[Boolean]


ConnectionBodyParametersList = List[ConnectionBodyParameter]


class ConnectionQueryStringParameter(TypedDict, total=False):
    Key: Optional[QueryStringKey]
    Value: Optional[QueryStringValue]
    IsValueSecret: Optional[Boolean]


ConnectionQueryStringParametersList = List[ConnectionQueryStringParameter]


class ConnectionHeaderParameter(TypedDict, total=False):
    Key: Optional[HeaderKey]
    Value: Optional[HeaderValue]
    IsValueSecret: Optional[Boolean]


ConnectionHeaderParametersList = List[ConnectionHeaderParameter]


class ConnectionHttpParameters(TypedDict, total=False):
    HeaderParameters: Optional[ConnectionHeaderParametersList]
    QueryStringParameters: Optional[ConnectionQueryStringParametersList]
    BodyParameters: Optional[ConnectionBodyParametersList]


class ConnectionOAuthClientResponseParameters(TypedDict, total=False):
    ClientID: Optional[AuthHeaderParameters]


class ConnectionOAuthResponseParameters(TypedDict, total=False):
    ClientParameters: Optional[ConnectionOAuthClientResponseParameters]
    AuthorizationEndpoint: Optional[HttpsEndpoint]
    HttpMethod: Optional[ConnectionOAuthHttpMethod]
    OAuthHttpParameters: Optional[ConnectionHttpParameters]


class ConnectionBasicAuthResponseParameters(TypedDict, total=False):
    Username: Optional[AuthHeaderParameters]


class ConnectionAuthResponseParameters(TypedDict, total=False):
    BasicAuthParameters: Optional[ConnectionBasicAuthResponseParameters]
    OAuthParameters: Optional[ConnectionOAuthResponseParameters]
    ApiKeyAuthParameters: Optional[ConnectionApiKeyAuthResponseParameters]
    InvocationHttpParameters: Optional[ConnectionHttpParameters]


ConnectionResponseList = List[Connection]


class CreateApiDestinationRequest(ServiceRequest):
    Name: ApiDestinationName
    Description: Optional[ApiDestinationDescription]
    ConnectionArn: ConnectionArn
    InvocationEndpoint: HttpsEndpoint
    HttpMethod: ApiDestinationHttpMethod
    InvocationRateLimitPerSecond: Optional[ApiDestinationInvocationRateLimitPerSecond]


class CreateApiDestinationResponse(TypedDict, total=False):
    ApiDestinationArn: Optional[ApiDestinationArn]
    ApiDestinationState: Optional[ApiDestinationState]
    CreationTime: Optional[Timestamp]
    LastModifiedTime: Optional[Timestamp]


class CreateArchiveRequest(ServiceRequest):
    ArchiveName: ArchiveName
    EventSourceArn: Arn
    Description: Optional[ArchiveDescription]
    EventPattern: Optional[EventPattern]
    RetentionDays: Optional[RetentionDays]


class CreateArchiveResponse(TypedDict, total=False):
    ArchiveArn: Optional[ArchiveArn]
    State: Optional[ArchiveState]
    StateReason: Optional[ArchiveStateReason]
    CreationTime: Optional[Timestamp]


class CreateConnectionApiKeyAuthRequestParameters(TypedDict, total=False):
    ApiKeyName: AuthHeaderParameters
    ApiKeyValue: AuthHeaderParameters


class CreateConnectionOAuthClientRequestParameters(TypedDict, total=False):
    ClientID: AuthHeaderParameters
    ClientSecret: AuthHeaderParameters


class CreateConnectionOAuthRequestParameters(TypedDict, total=False):
    ClientParameters: CreateConnectionOAuthClientRequestParameters
    AuthorizationEndpoint: HttpsEndpoint
    HttpMethod: ConnectionOAuthHttpMethod
    OAuthHttpParameters: Optional[ConnectionHttpParameters]


class CreateConnectionBasicAuthRequestParameters(TypedDict, total=False):
    Username: AuthHeaderParameters
    Password: AuthHeaderParameters


class CreateConnectionAuthRequestParameters(TypedDict, total=False):
    BasicAuthParameters: Optional[CreateConnectionBasicAuthRequestParameters]
    OAuthParameters: Optional[CreateConnectionOAuthRequestParameters]
    ApiKeyAuthParameters: Optional[CreateConnectionApiKeyAuthRequestParameters]
    InvocationHttpParameters: Optional[ConnectionHttpParameters]


class CreateConnectionRequest(ServiceRequest):
    Name: ConnectionName
    Description: Optional[ConnectionDescription]
    AuthorizationType: ConnectionAuthorizationType
    AuthParameters: CreateConnectionAuthRequestParameters


class CreateConnectionResponse(TypedDict, total=False):
    ConnectionArn: Optional[ConnectionArn]
    ConnectionState: Optional[ConnectionState]
    CreationTime: Optional[Timestamp]
    LastModifiedTime: Optional[Timestamp]


class EndpointEventBus(TypedDict, total=False):
    EventBusArn: NonPartnerEventBusArn


EndpointEventBusList = List[EndpointEventBus]


class ReplicationConfig(TypedDict, total=False):
    State: Optional[ReplicationState]


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
    Description: Optional[EndpointDescription]
    RoutingConfig: RoutingConfig
    ReplicationConfig: Optional[ReplicationConfig]
    EventBuses: EndpointEventBusList
    RoleArn: Optional[IamRoleArn]


class CreateEndpointResponse(TypedDict, total=False):
    Name: Optional[EndpointName]
    Arn: Optional[EndpointArn]
    RoutingConfig: Optional[RoutingConfig]
    ReplicationConfig: Optional[ReplicationConfig]
    EventBuses: Optional[EndpointEventBusList]
    RoleArn: Optional[IamRoleArn]
    State: Optional[EndpointState]


class Tag(TypedDict, total=False):
    Key: TagKey
    Value: TagValue


TagList = List[Tag]


class CreateEventBusRequest(ServiceRequest):
    Name: EventBusName
    EventSourceName: Optional[EventSourceName]
    Tags: Optional[TagList]


class CreateEventBusResponse(TypedDict, total=False):
    EventBusArn: Optional[String]


class CreatePartnerEventSourceRequest(ServiceRequest):
    Name: EventSourceName
    Account: AccountId


class CreatePartnerEventSourceResponse(TypedDict, total=False):
    EventSourceArn: Optional[String]


class DeactivateEventSourceRequest(ServiceRequest):
    Name: EventSourceName


class DeadLetterConfig(TypedDict, total=False):
    Arn: Optional[ResourceArn]


class DeauthorizeConnectionRequest(ServiceRequest):
    Name: ConnectionName


class DeauthorizeConnectionResponse(TypedDict, total=False):
    ConnectionArn: Optional[ConnectionArn]
    ConnectionState: Optional[ConnectionState]
    CreationTime: Optional[Timestamp]
    LastModifiedTime: Optional[Timestamp]
    LastAuthorizedTime: Optional[Timestamp]


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
    ConnectionArn: Optional[ConnectionArn]
    ConnectionState: Optional[ConnectionState]
    CreationTime: Optional[Timestamp]
    LastModifiedTime: Optional[Timestamp]
    LastAuthorizedTime: Optional[Timestamp]


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
    EventBusName: Optional[EventBusNameOrArn]
    Force: Optional[Boolean]


class DescribeApiDestinationRequest(ServiceRequest):
    Name: ApiDestinationName


class DescribeApiDestinationResponse(TypedDict, total=False):
    ApiDestinationArn: Optional[ApiDestinationArn]
    Name: Optional[ApiDestinationName]
    Description: Optional[ApiDestinationDescription]
    ApiDestinationState: Optional[ApiDestinationState]
    ConnectionArn: Optional[ConnectionArn]
    InvocationEndpoint: Optional[HttpsEndpoint]
    HttpMethod: Optional[ApiDestinationHttpMethod]
    InvocationRateLimitPerSecond: Optional[ApiDestinationInvocationRateLimitPerSecond]
    CreationTime: Optional[Timestamp]
    LastModifiedTime: Optional[Timestamp]


class DescribeArchiveRequest(ServiceRequest):
    ArchiveName: ArchiveName


class DescribeArchiveResponse(TypedDict, total=False):
    ArchiveArn: Optional[ArchiveArn]
    ArchiveName: Optional[ArchiveName]
    EventSourceArn: Optional[Arn]
    Description: Optional[ArchiveDescription]
    EventPattern: Optional[EventPattern]
    State: Optional[ArchiveState]
    StateReason: Optional[ArchiveStateReason]
    RetentionDays: Optional[RetentionDays]
    SizeBytes: Optional[Long]
    EventCount: Optional[Long]
    CreationTime: Optional[Timestamp]


class DescribeConnectionRequest(ServiceRequest):
    Name: ConnectionName


class DescribeConnectionResponse(TypedDict, total=False):
    ConnectionArn: Optional[ConnectionArn]
    Name: Optional[ConnectionName]
    Description: Optional[ConnectionDescription]
    ConnectionState: Optional[ConnectionState]
    StateReason: Optional[ConnectionStateReason]
    AuthorizationType: Optional[ConnectionAuthorizationType]
    SecretArn: Optional[SecretsManagerSecretArn]
    AuthParameters: Optional[ConnectionAuthResponseParameters]
    CreationTime: Optional[Timestamp]
    LastModifiedTime: Optional[Timestamp]
    LastAuthorizedTime: Optional[Timestamp]


class DescribeEndpointRequest(ServiceRequest):
    Name: EndpointName
    HomeRegion: Optional[HomeRegion]


class DescribeEndpointResponse(TypedDict, total=False):
    Name: Optional[EndpointName]
    Description: Optional[EndpointDescription]
    Arn: Optional[EndpointArn]
    RoutingConfig: Optional[RoutingConfig]
    ReplicationConfig: Optional[ReplicationConfig]
    EventBuses: Optional[EndpointEventBusList]
    RoleArn: Optional[IamRoleArn]
    EndpointId: Optional[EndpointId]
    EndpointUrl: Optional[EndpointUrl]
    State: Optional[EndpointState]
    StateReason: Optional[EndpointStateReason]
    CreationTime: Optional[Timestamp]
    LastModifiedTime: Optional[Timestamp]


class DescribeEventBusRequest(ServiceRequest):
    Name: Optional[EventBusNameOrArn]


class DescribeEventBusResponse(TypedDict, total=False):
    Name: Optional[String]
    Arn: Optional[String]
    Policy: Optional[String]


class DescribeEventSourceRequest(ServiceRequest):
    Name: EventSourceName


class DescribeEventSourceResponse(TypedDict, total=False):
    Arn: Optional[String]
    CreatedBy: Optional[String]
    CreationTime: Optional[Timestamp]
    ExpirationTime: Optional[Timestamp]
    Name: Optional[String]
    State: Optional[EventSourceState]


class DescribePartnerEventSourceRequest(ServiceRequest):
    Name: EventSourceName


class DescribePartnerEventSourceResponse(TypedDict, total=False):
    Arn: Optional[String]
    Name: Optional[String]


class DescribeReplayRequest(ServiceRequest):
    ReplayName: ReplayName


ReplayDestinationFilters = List[Arn]


class ReplayDestination(TypedDict, total=False):
    Arn: Arn
    FilterArns: Optional[ReplayDestinationFilters]


class DescribeReplayResponse(TypedDict, total=False):
    ReplayName: Optional[ReplayName]
    ReplayArn: Optional[ReplayArn]
    Description: Optional[ReplayDescription]
    State: Optional[ReplayState]
    StateReason: Optional[ReplayStateReason]
    EventSourceArn: Optional[Arn]
    Destination: Optional[ReplayDestination]
    EventStartTime: Optional[Timestamp]
    EventEndTime: Optional[Timestamp]
    EventLastReplayedTime: Optional[Timestamp]
    ReplayStartTime: Optional[Timestamp]
    ReplayEndTime: Optional[Timestamp]


class DescribeRuleRequest(ServiceRequest):
    Name: RuleName
    EventBusName: Optional[EventBusNameOrArn]


class DescribeRuleResponse(TypedDict, total=False):
    Name: Optional[RuleName]
    Arn: Optional[RuleArn]
    EventPattern: Optional[EventPattern]
    ScheduleExpression: Optional[ScheduleExpression]
    State: Optional[RuleState]
    Description: Optional[RuleDescription]
    RoleArn: Optional[RoleArn]
    ManagedBy: Optional[ManagedBy]
    EventBusName: Optional[EventBusName]
    CreatedBy: Optional[CreatedBy]


class DisableRuleRequest(ServiceRequest):
    Name: RuleName
    EventBusName: Optional[EventBusNameOrArn]


PlacementStrategy = TypedDict(
    "PlacementStrategy",
    {
        "type": Optional[PlacementStrategyType],
        "field": Optional[PlacementStrategyField],
    },
    total=False,
)
PlacementStrategies = List[PlacementStrategy]
PlacementConstraint = TypedDict(
    "PlacementConstraint",
    {
        "type": Optional[PlacementConstraintType],
        "expression": Optional[PlacementConstraintExpression],
    },
    total=False,
)
PlacementConstraints = List[PlacementConstraint]


class NetworkConfiguration(TypedDict, total=False):
    awsvpcConfiguration: Optional[AwsVpcConfiguration]


class EcsParameters(TypedDict, total=False):
    TaskDefinitionArn: Arn
    TaskCount: Optional[LimitMin1]
    LaunchType: Optional[LaunchType]
    NetworkConfiguration: Optional[NetworkConfiguration]
    PlatformVersion: Optional[String]
    Group: Optional[String]
    CapacityProviderStrategy: Optional[CapacityProviderStrategy]
    EnableECSManagedTags: Optional[Boolean]
    EnableExecuteCommand: Optional[Boolean]
    PlacementConstraints: Optional[PlacementConstraints]
    PlacementStrategy: Optional[PlacementStrategies]
    PropagateTags: Optional[PropagateTags]
    ReferenceId: Optional[ReferenceId]
    Tags: Optional[TagList]


class EnableRuleRequest(ServiceRequest):
    Name: RuleName
    EventBusName: Optional[EventBusNameOrArn]


class Endpoint(TypedDict, total=False):
    Name: Optional[EndpointName]
    Description: Optional[EndpointDescription]
    Arn: Optional[EndpointArn]
    RoutingConfig: Optional[RoutingConfig]
    ReplicationConfig: Optional[ReplicationConfig]
    EventBuses: Optional[EndpointEventBusList]
    RoleArn: Optional[IamRoleArn]
    EndpointId: Optional[EndpointId]
    EndpointUrl: Optional[EndpointUrl]
    State: Optional[EndpointState]
    StateReason: Optional[EndpointStateReason]
    CreationTime: Optional[Timestamp]
    LastModifiedTime: Optional[Timestamp]


EndpointList = List[Endpoint]


class EventBus(TypedDict, total=False):
    Name: Optional[String]
    Arn: Optional[String]
    Policy: Optional[String]


EventBusList = List[EventBus]
EventResourceList = List[EventResource]


class EventSource(TypedDict, total=False):
    Arn: Optional[String]
    CreatedBy: Optional[String]
    CreationTime: Optional[Timestamp]
    ExpirationTime: Optional[Timestamp]
    Name: Optional[String]
    State: Optional[EventSourceState]


EventSourceList = List[EventSource]
EventTime = datetime
HeaderParametersMap = Dict[HeaderKey, HeaderValue]
QueryStringParametersMap = Dict[QueryStringKey, QueryStringValue]
PathParameterList = List[PathParameter]


class HttpParameters(TypedDict, total=False):
    PathParameterValues: Optional[PathParameterList]
    HeaderParameters: Optional[HeaderParametersMap]
    QueryStringParameters: Optional[QueryStringParametersMap]


TransformerPaths = Dict[InputTransformerPathKey, TargetInputPath]


class InputTransformer(TypedDict, total=False):
    InputPathsMap: Optional[TransformerPaths]
    InputTemplate: TransformerInput


class KinesisParameters(TypedDict, total=False):
    PartitionKeyPath: TargetPartitionKeyPath


class ListApiDestinationsRequest(ServiceRequest):
    NamePrefix: Optional[ApiDestinationName]
    ConnectionArn: Optional[ConnectionArn]
    NextToken: Optional[NextToken]
    Limit: Optional[LimitMax100]


class ListApiDestinationsResponse(TypedDict, total=False):
    ApiDestinations: Optional[ApiDestinationResponseList]
    NextToken: Optional[NextToken]


class ListArchivesRequest(ServiceRequest):
    NamePrefix: Optional[ArchiveName]
    EventSourceArn: Optional[Arn]
    State: Optional[ArchiveState]
    NextToken: Optional[NextToken]
    Limit: Optional[LimitMax100]


class ListArchivesResponse(TypedDict, total=False):
    Archives: Optional[ArchiveResponseList]
    NextToken: Optional[NextToken]


class ListConnectionsRequest(ServiceRequest):
    NamePrefix: Optional[ConnectionName]
    ConnectionState: Optional[ConnectionState]
    NextToken: Optional[NextToken]
    Limit: Optional[LimitMax100]


class ListConnectionsResponse(TypedDict, total=False):
    Connections: Optional[ConnectionResponseList]
    NextToken: Optional[NextToken]


class ListEndpointsRequest(ServiceRequest):
    NamePrefix: Optional[EndpointName]
    HomeRegion: Optional[HomeRegion]
    NextToken: Optional[NextToken]
    MaxResults: Optional[LimitMax100]


class ListEndpointsResponse(TypedDict, total=False):
    Endpoints: Optional[EndpointList]
    NextToken: Optional[NextToken]


class ListEventBusesRequest(ServiceRequest):
    NamePrefix: Optional[EventBusName]
    NextToken: Optional[NextToken]
    Limit: Optional[LimitMax100]


class ListEventBusesResponse(TypedDict, total=False):
    EventBuses: Optional[EventBusList]
    NextToken: Optional[NextToken]


class ListEventSourcesRequest(ServiceRequest):
    NamePrefix: Optional[EventSourceNamePrefix]
    NextToken: Optional[NextToken]
    Limit: Optional[LimitMax100]


class ListEventSourcesResponse(TypedDict, total=False):
    EventSources: Optional[EventSourceList]
    NextToken: Optional[NextToken]


class ListPartnerEventSourceAccountsRequest(ServiceRequest):
    EventSourceName: EventSourceName
    NextToken: Optional[NextToken]
    Limit: Optional[LimitMax100]


class PartnerEventSourceAccount(TypedDict, total=False):
    Account: Optional[AccountId]
    CreationTime: Optional[Timestamp]
    ExpirationTime: Optional[Timestamp]
    State: Optional[EventSourceState]


PartnerEventSourceAccountList = List[PartnerEventSourceAccount]


class ListPartnerEventSourceAccountsResponse(TypedDict, total=False):
    PartnerEventSourceAccounts: Optional[PartnerEventSourceAccountList]
    NextToken: Optional[NextToken]


class ListPartnerEventSourcesRequest(ServiceRequest):
    NamePrefix: PartnerEventSourceNamePrefix
    NextToken: Optional[NextToken]
    Limit: Optional[LimitMax100]


class PartnerEventSource(TypedDict, total=False):
    Arn: Optional[String]
    Name: Optional[String]


PartnerEventSourceList = List[PartnerEventSource]


class ListPartnerEventSourcesResponse(TypedDict, total=False):
    PartnerEventSources: Optional[PartnerEventSourceList]
    NextToken: Optional[NextToken]


class ListReplaysRequest(ServiceRequest):
    NamePrefix: Optional[ReplayName]
    State: Optional[ReplayState]
    EventSourceArn: Optional[Arn]
    NextToken: Optional[NextToken]
    Limit: Optional[LimitMax100]


class Replay(TypedDict, total=False):
    ReplayName: Optional[ReplayName]
    EventSourceArn: Optional[Arn]
    State: Optional[ReplayState]
    StateReason: Optional[ReplayStateReason]
    EventStartTime: Optional[Timestamp]
    EventEndTime: Optional[Timestamp]
    EventLastReplayedTime: Optional[Timestamp]
    ReplayStartTime: Optional[Timestamp]
    ReplayEndTime: Optional[Timestamp]


ReplayList = List[Replay]


class ListReplaysResponse(TypedDict, total=False):
    Replays: Optional[ReplayList]
    NextToken: Optional[NextToken]


class ListRuleNamesByTargetRequest(ServiceRequest):
    TargetArn: TargetArn
    EventBusName: Optional[EventBusNameOrArn]
    NextToken: Optional[NextToken]
    Limit: Optional[LimitMax100]


RuleNameList = List[RuleName]


class ListRuleNamesByTargetResponse(TypedDict, total=False):
    RuleNames: Optional[RuleNameList]
    NextToken: Optional[NextToken]


class ListRulesRequest(ServiceRequest):
    NamePrefix: Optional[RuleName]
    EventBusName: Optional[EventBusNameOrArn]
    NextToken: Optional[NextToken]
    Limit: Optional[LimitMax100]


class Rule(TypedDict, total=False):
    Name: Optional[RuleName]
    Arn: Optional[RuleArn]
    EventPattern: Optional[EventPattern]
    State: Optional[RuleState]
    Description: Optional[RuleDescription]
    ScheduleExpression: Optional[ScheduleExpression]
    RoleArn: Optional[RoleArn]
    ManagedBy: Optional[ManagedBy]
    EventBusName: Optional[EventBusName]


RuleResponseList = List[Rule]


class ListRulesResponse(TypedDict, total=False):
    Rules: Optional[RuleResponseList]
    NextToken: Optional[NextToken]


class ListTagsForResourceRequest(ServiceRequest):
    ResourceARN: Arn


class ListTagsForResourceResponse(TypedDict, total=False):
    Tags: Optional[TagList]


class ListTargetsByRuleRequest(ServiceRequest):
    Rule: RuleName
    EventBusName: Optional[EventBusNameOrArn]
    NextToken: Optional[NextToken]
    Limit: Optional[LimitMax100]


class RetryPolicy(TypedDict, total=False):
    MaximumRetryAttempts: Optional[MaximumRetryAttempts]
    MaximumEventAgeInSeconds: Optional[MaximumEventAgeInSeconds]


class SageMakerPipelineParameter(TypedDict, total=False):
    Name: SageMakerPipelineParameterName
    Value: SageMakerPipelineParameterValue


SageMakerPipelineParameterList = List[SageMakerPipelineParameter]


class SageMakerPipelineParameters(TypedDict, total=False):
    PipelineParameterList: Optional[SageMakerPipelineParameterList]


class RedshiftDataParameters(TypedDict, total=False):
    SecretManagerArn: Optional[RedshiftSecretManagerArn]
    Database: Database
    DbUser: Optional[DbUser]
    Sql: Sql
    StatementName: Optional[StatementName]
    WithEvent: Optional[Boolean]


class SqsParameters(TypedDict, total=False):
    MessageGroupId: Optional[MessageGroupId]


RunCommandTargetValues = List[RunCommandTargetValue]


class RunCommandTarget(TypedDict, total=False):
    Key: RunCommandTargetKey
    Values: RunCommandTargetValues


RunCommandTargets = List[RunCommandTarget]


class RunCommandParameters(TypedDict, total=False):
    RunCommandTargets: RunCommandTargets


class Target(TypedDict, total=False):
    Id: TargetId
    Arn: TargetArn
    RoleArn: Optional[RoleArn]
    Input: Optional[TargetInput]
    InputPath: Optional[TargetInputPath]
    InputTransformer: Optional[InputTransformer]
    KinesisParameters: Optional[KinesisParameters]
    RunCommandParameters: Optional[RunCommandParameters]
    EcsParameters: Optional[EcsParameters]
    BatchParameters: Optional[BatchParameters]
    SqsParameters: Optional[SqsParameters]
    HttpParameters: Optional[HttpParameters]
    RedshiftDataParameters: Optional[RedshiftDataParameters]
    SageMakerPipelineParameters: Optional[SageMakerPipelineParameters]
    DeadLetterConfig: Optional[DeadLetterConfig]
    RetryPolicy: Optional[RetryPolicy]


TargetList = List[Target]


class ListTargetsByRuleResponse(TypedDict, total=False):
    Targets: Optional[TargetList]
    NextToken: Optional[NextToken]


class PutEventsRequestEntry(TypedDict, total=False):
    Time: Optional[EventTime]
    Source: Optional[String]
    Resources: Optional[EventResourceList]
    DetailType: Optional[String]
    Detail: Optional[String]
    EventBusName: Optional[NonPartnerEventBusNameOrArn]
    TraceHeader: Optional[TraceHeader]


PutEventsRequestEntryList = List[PutEventsRequestEntry]


class PutEventsRequest(ServiceRequest):
    Entries: PutEventsRequestEntryList
    EndpointId: Optional[EndpointId]


class PutEventsResultEntry(TypedDict, total=False):
    EventId: Optional[EventId]
    ErrorCode: Optional[ErrorCode]
    ErrorMessage: Optional[ErrorMessage]


PutEventsResultEntryList = List[PutEventsResultEntry]


class PutEventsResponse(TypedDict, total=False):
    FailedEntryCount: Optional[Integer]
    Entries: Optional[PutEventsResultEntryList]


class PutPartnerEventsRequestEntry(TypedDict, total=False):
    Time: Optional[EventTime]
    Source: Optional[EventSourceName]
    Resources: Optional[EventResourceList]
    DetailType: Optional[String]
    Detail: Optional[String]


PutPartnerEventsRequestEntryList = List[PutPartnerEventsRequestEntry]


class PutPartnerEventsRequest(ServiceRequest):
    Entries: PutPartnerEventsRequestEntryList


class PutPartnerEventsResultEntry(TypedDict, total=False):
    EventId: Optional[EventId]
    ErrorCode: Optional[ErrorCode]
    ErrorMessage: Optional[ErrorMessage]


PutPartnerEventsResultEntryList = List[PutPartnerEventsResultEntry]


class PutPartnerEventsResponse(TypedDict, total=False):
    FailedEntryCount: Optional[Integer]
    Entries: Optional[PutPartnerEventsResultEntryList]


class PutPermissionRequest(ServiceRequest):
    EventBusName: Optional[NonPartnerEventBusName]
    Action: Optional[Action]
    Principal: Optional[Principal]
    StatementId: Optional[StatementId]
    Condition: Optional[Condition]
    Policy: Optional[String]


class PutRuleRequest(ServiceRequest):
    Name: RuleName
    ScheduleExpression: Optional[ScheduleExpression]
    EventPattern: Optional[EventPattern]
    State: Optional[RuleState]
    Description: Optional[RuleDescription]
    RoleArn: Optional[RoleArn]
    Tags: Optional[TagList]
    EventBusName: Optional[EventBusNameOrArn]


class PutRuleResponse(TypedDict, total=False):
    RuleArn: Optional[RuleArn]


class PutTargetsRequest(ServiceRequest):
    Rule: RuleName
    EventBusName: Optional[EventBusNameOrArn]
    Targets: TargetList


class PutTargetsResultEntry(TypedDict, total=False):
    TargetId: Optional[TargetId]
    ErrorCode: Optional[ErrorCode]
    ErrorMessage: Optional[ErrorMessage]


PutTargetsResultEntryList = List[PutTargetsResultEntry]


class PutTargetsResponse(TypedDict, total=False):
    FailedEntryCount: Optional[Integer]
    FailedEntries: Optional[PutTargetsResultEntryList]


class RemovePermissionRequest(ServiceRequest):
    StatementId: Optional[StatementId]
    RemoveAllPermissions: Optional[Boolean]
    EventBusName: Optional[NonPartnerEventBusName]


TargetIdList = List[TargetId]


class RemoveTargetsRequest(ServiceRequest):
    Rule: RuleName
    EventBusName: Optional[EventBusNameOrArn]
    Ids: TargetIdList
    Force: Optional[Boolean]


class RemoveTargetsResultEntry(TypedDict, total=False):
    TargetId: Optional[TargetId]
    ErrorCode: Optional[ErrorCode]
    ErrorMessage: Optional[ErrorMessage]


RemoveTargetsResultEntryList = List[RemoveTargetsResultEntry]


class RemoveTargetsResponse(TypedDict, total=False):
    FailedEntryCount: Optional[Integer]
    FailedEntries: Optional[RemoveTargetsResultEntryList]


class StartReplayRequest(ServiceRequest):
    ReplayName: ReplayName
    Description: Optional[ReplayDescription]
    EventSourceArn: Arn
    EventStartTime: Timestamp
    EventEndTime: Timestamp
    Destination: ReplayDestination


class StartReplayResponse(TypedDict, total=False):
    ReplayArn: Optional[ReplayArn]
    State: Optional[ReplayState]
    StateReason: Optional[ReplayStateReason]
    ReplayStartTime: Optional[Timestamp]


TagKeyList = List[TagKey]


class TagResourceRequest(ServiceRequest):
    ResourceARN: Arn
    Tags: TagList


class TagResourceResponse(TypedDict, total=False):
    pass


class TestEventPatternRequest(ServiceRequest):
    EventPattern: EventPattern
    Event: String


class TestEventPatternResponse(TypedDict, total=False):
    Result: Optional[Boolean]


class UntagResourceRequest(ServiceRequest):
    ResourceARN: Arn
    TagKeys: TagKeyList


class UntagResourceResponse(TypedDict, total=False):
    pass


class UpdateApiDestinationRequest(ServiceRequest):
    Name: ApiDestinationName
    Description: Optional[ApiDestinationDescription]
    ConnectionArn: Optional[ConnectionArn]
    InvocationEndpoint: Optional[HttpsEndpoint]
    HttpMethod: Optional[ApiDestinationHttpMethod]
    InvocationRateLimitPerSecond: Optional[ApiDestinationInvocationRateLimitPerSecond]


class UpdateApiDestinationResponse(TypedDict, total=False):
    ApiDestinationArn: Optional[ApiDestinationArn]
    ApiDestinationState: Optional[ApiDestinationState]
    CreationTime: Optional[Timestamp]
    LastModifiedTime: Optional[Timestamp]


class UpdateArchiveRequest(ServiceRequest):
    ArchiveName: ArchiveName
    Description: Optional[ArchiveDescription]
    EventPattern: Optional[EventPattern]
    RetentionDays: Optional[RetentionDays]


class UpdateArchiveResponse(TypedDict, total=False):
    ArchiveArn: Optional[ArchiveArn]
    State: Optional[ArchiveState]
    StateReason: Optional[ArchiveStateReason]
    CreationTime: Optional[Timestamp]


class UpdateConnectionApiKeyAuthRequestParameters(TypedDict, total=False):
    ApiKeyName: Optional[AuthHeaderParameters]
    ApiKeyValue: Optional[AuthHeaderParameters]


class UpdateConnectionOAuthClientRequestParameters(TypedDict, total=False):
    ClientID: Optional[AuthHeaderParameters]
    ClientSecret: Optional[AuthHeaderParameters]


class UpdateConnectionOAuthRequestParameters(TypedDict, total=False):
    ClientParameters: Optional[UpdateConnectionOAuthClientRequestParameters]
    AuthorizationEndpoint: Optional[HttpsEndpoint]
    HttpMethod: Optional[ConnectionOAuthHttpMethod]
    OAuthHttpParameters: Optional[ConnectionHttpParameters]


class UpdateConnectionBasicAuthRequestParameters(TypedDict, total=False):
    Username: Optional[AuthHeaderParameters]
    Password: Optional[AuthHeaderParameters]


class UpdateConnectionAuthRequestParameters(TypedDict, total=False):
    BasicAuthParameters: Optional[UpdateConnectionBasicAuthRequestParameters]
    OAuthParameters: Optional[UpdateConnectionOAuthRequestParameters]
    ApiKeyAuthParameters: Optional[UpdateConnectionApiKeyAuthRequestParameters]
    InvocationHttpParameters: Optional[ConnectionHttpParameters]


class UpdateConnectionRequest(ServiceRequest):
    Name: ConnectionName
    Description: Optional[ConnectionDescription]
    AuthorizationType: Optional[ConnectionAuthorizationType]
    AuthParameters: Optional[UpdateConnectionAuthRequestParameters]


class UpdateConnectionResponse(TypedDict, total=False):
    ConnectionArn: Optional[ConnectionArn]
    ConnectionState: Optional[ConnectionState]
    CreationTime: Optional[Timestamp]
    LastModifiedTime: Optional[Timestamp]
    LastAuthorizedTime: Optional[Timestamp]


class UpdateEndpointRequest(ServiceRequest):
    Name: EndpointName
    Description: Optional[EndpointDescription]
    RoutingConfig: Optional[RoutingConfig]
    ReplicationConfig: Optional[ReplicationConfig]
    EventBuses: Optional[EndpointEventBusList]
    RoleArn: Optional[IamRoleArn]


class UpdateEndpointResponse(TypedDict, total=False):
    Name: Optional[EndpointName]
    Arn: Optional[EndpointArn]
    RoutingConfig: Optional[RoutingConfig]
    ReplicationConfig: Optional[ReplicationConfig]
    EventBuses: Optional[EndpointEventBusList]
    RoleArn: Optional[IamRoleArn]
    EndpointId: Optional[EndpointId]
    EndpointUrl: Optional[EndpointUrl]
    State: Optional[EndpointState]


class EventsApi:

    service = "events"
    version = "2015-10-07"

    @handler("ActivateEventSource")
    def activate_event_source(self, context: RequestContext, name: EventSourceName) -> None:
        raise NotImplementedError

    @handler("CancelReplay")
    def cancel_replay(
        self, context: RequestContext, replay_name: ReplayName
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
        description: ApiDestinationDescription = None,
        invocation_rate_limit_per_second: ApiDestinationInvocationRateLimitPerSecond = None,
    ) -> CreateApiDestinationResponse:
        raise NotImplementedError

    @handler("CreateArchive")
    def create_archive(
        self,
        context: RequestContext,
        archive_name: ArchiveName,
        event_source_arn: Arn,
        description: ArchiveDescription = None,
        event_pattern: EventPattern = None,
        retention_days: RetentionDays = None,
    ) -> CreateArchiveResponse:
        raise NotImplementedError

    @handler("CreateConnection")
    def create_connection(
        self,
        context: RequestContext,
        name: ConnectionName,
        authorization_type: ConnectionAuthorizationType,
        auth_parameters: CreateConnectionAuthRequestParameters,
        description: ConnectionDescription = None,
    ) -> CreateConnectionResponse:
        raise NotImplementedError

    @handler("CreateEndpoint")
    def create_endpoint(
        self,
        context: RequestContext,
        name: EndpointName,
        routing_config: RoutingConfig,
        event_buses: EndpointEventBusList,
        description: EndpointDescription = None,
        replication_config: ReplicationConfig = None,
        role_arn: IamRoleArn = None,
    ) -> CreateEndpointResponse:
        raise NotImplementedError

    @handler("CreateEventBus")
    def create_event_bus(
        self,
        context: RequestContext,
        name: EventBusName,
        event_source_name: EventSourceName = None,
        tags: TagList = None,
    ) -> CreateEventBusResponse:
        raise NotImplementedError

    @handler("CreatePartnerEventSource")
    def create_partner_event_source(
        self, context: RequestContext, name: EventSourceName, account: AccountId
    ) -> CreatePartnerEventSourceResponse:
        raise NotImplementedError

    @handler("DeactivateEventSource")
    def deactivate_event_source(self, context: RequestContext, name: EventSourceName) -> None:
        raise NotImplementedError

    @handler("DeauthorizeConnection")
    def deauthorize_connection(
        self, context: RequestContext, name: ConnectionName
    ) -> DeauthorizeConnectionResponse:
        raise NotImplementedError

    @handler("DeleteApiDestination")
    def delete_api_destination(
        self, context: RequestContext, name: ApiDestinationName
    ) -> DeleteApiDestinationResponse:
        raise NotImplementedError

    @handler("DeleteArchive")
    def delete_archive(
        self, context: RequestContext, archive_name: ArchiveName
    ) -> DeleteArchiveResponse:
        raise NotImplementedError

    @handler("DeleteConnection")
    def delete_connection(
        self, context: RequestContext, name: ConnectionName
    ) -> DeleteConnectionResponse:
        raise NotImplementedError

    @handler("DeleteEndpoint")
    def delete_endpoint(
        self, context: RequestContext, name: EndpointName
    ) -> DeleteEndpointResponse:
        raise NotImplementedError

    @handler("DeleteEventBus")
    def delete_event_bus(self, context: RequestContext, name: EventBusName) -> None:
        raise NotImplementedError

    @handler("DeletePartnerEventSource")
    def delete_partner_event_source(
        self, context: RequestContext, name: EventSourceName, account: AccountId
    ) -> None:
        raise NotImplementedError

    @handler("DeleteRule")
    def delete_rule(
        self,
        context: RequestContext,
        name: RuleName,
        event_bus_name: EventBusNameOrArn = None,
        force: Boolean = None,
    ) -> None:
        raise NotImplementedError

    @handler("DescribeApiDestination")
    def describe_api_destination(
        self, context: RequestContext, name: ApiDestinationName
    ) -> DescribeApiDestinationResponse:
        raise NotImplementedError

    @handler("DescribeArchive")
    def describe_archive(
        self, context: RequestContext, archive_name: ArchiveName
    ) -> DescribeArchiveResponse:
        raise NotImplementedError

    @handler("DescribeConnection")
    def describe_connection(
        self, context: RequestContext, name: ConnectionName
    ) -> DescribeConnectionResponse:
        raise NotImplementedError

    @handler("DescribeEndpoint")
    def describe_endpoint(
        self, context: RequestContext, name: EndpointName, home_region: HomeRegion = None
    ) -> DescribeEndpointResponse:
        raise NotImplementedError

    @handler("DescribeEventBus")
    def describe_event_bus(
        self, context: RequestContext, name: EventBusNameOrArn = None
    ) -> DescribeEventBusResponse:
        raise NotImplementedError

    @handler("DescribeEventSource")
    def describe_event_source(
        self, context: RequestContext, name: EventSourceName
    ) -> DescribeEventSourceResponse:
        raise NotImplementedError

    @handler("DescribePartnerEventSource")
    def describe_partner_event_source(
        self, context: RequestContext, name: EventSourceName
    ) -> DescribePartnerEventSourceResponse:
        raise NotImplementedError

    @handler("DescribeReplay")
    def describe_replay(
        self, context: RequestContext, replay_name: ReplayName
    ) -> DescribeReplayResponse:
        raise NotImplementedError

    @handler("DescribeRule")
    def describe_rule(
        self, context: RequestContext, name: RuleName, event_bus_name: EventBusNameOrArn = None
    ) -> DescribeRuleResponse:
        raise NotImplementedError

    @handler("DisableRule")
    def disable_rule(
        self, context: RequestContext, name: RuleName, event_bus_name: EventBusNameOrArn = None
    ) -> None:
        raise NotImplementedError

    @handler("EnableRule")
    def enable_rule(
        self, context: RequestContext, name: RuleName, event_bus_name: EventBusNameOrArn = None
    ) -> None:
        raise NotImplementedError

    @handler("ListApiDestinations")
    def list_api_destinations(
        self,
        context: RequestContext,
        name_prefix: ApiDestinationName = None,
        connection_arn: ConnectionArn = None,
        next_token: NextToken = None,
        limit: LimitMax100 = None,
    ) -> ListApiDestinationsResponse:
        raise NotImplementedError

    @handler("ListArchives")
    def list_archives(
        self,
        context: RequestContext,
        name_prefix: ArchiveName = None,
        event_source_arn: Arn = None,
        state: ArchiveState = None,
        next_token: NextToken = None,
        limit: LimitMax100 = None,
    ) -> ListArchivesResponse:
        raise NotImplementedError

    @handler("ListConnections")
    def list_connections(
        self,
        context: RequestContext,
        name_prefix: ConnectionName = None,
        connection_state: ConnectionState = None,
        next_token: NextToken = None,
        limit: LimitMax100 = None,
    ) -> ListConnectionsResponse:
        raise NotImplementedError

    @handler("ListEndpoints")
    def list_endpoints(
        self,
        context: RequestContext,
        name_prefix: EndpointName = None,
        home_region: HomeRegion = None,
        next_token: NextToken = None,
        max_results: LimitMax100 = None,
    ) -> ListEndpointsResponse:
        raise NotImplementedError

    @handler("ListEventBuses")
    def list_event_buses(
        self,
        context: RequestContext,
        name_prefix: EventBusName = None,
        next_token: NextToken = None,
        limit: LimitMax100 = None,
    ) -> ListEventBusesResponse:
        raise NotImplementedError

    @handler("ListEventSources")
    def list_event_sources(
        self,
        context: RequestContext,
        name_prefix: EventSourceNamePrefix = None,
        next_token: NextToken = None,
        limit: LimitMax100 = None,
    ) -> ListEventSourcesResponse:
        raise NotImplementedError

    @handler("ListPartnerEventSourceAccounts")
    def list_partner_event_source_accounts(
        self,
        context: RequestContext,
        event_source_name: EventSourceName,
        next_token: NextToken = None,
        limit: LimitMax100 = None,
    ) -> ListPartnerEventSourceAccountsResponse:
        raise NotImplementedError

    @handler("ListPartnerEventSources")
    def list_partner_event_sources(
        self,
        context: RequestContext,
        name_prefix: PartnerEventSourceNamePrefix,
        next_token: NextToken = None,
        limit: LimitMax100 = None,
    ) -> ListPartnerEventSourcesResponse:
        raise NotImplementedError

    @handler("ListReplays")
    def list_replays(
        self,
        context: RequestContext,
        name_prefix: ReplayName = None,
        state: ReplayState = None,
        event_source_arn: Arn = None,
        next_token: NextToken = None,
        limit: LimitMax100 = None,
    ) -> ListReplaysResponse:
        raise NotImplementedError

    @handler("ListRuleNamesByTarget")
    def list_rule_names_by_target(
        self,
        context: RequestContext,
        target_arn: TargetArn,
        event_bus_name: EventBusNameOrArn = None,
        next_token: NextToken = None,
        limit: LimitMax100 = None,
    ) -> ListRuleNamesByTargetResponse:
        raise NotImplementedError

    @handler("ListRules")
    def list_rules(
        self,
        context: RequestContext,
        name_prefix: RuleName = None,
        event_bus_name: EventBusNameOrArn = None,
        next_token: NextToken = None,
        limit: LimitMax100 = None,
    ) -> ListRulesResponse:
        raise NotImplementedError

    @handler("ListTagsForResource")
    def list_tags_for_resource(
        self, context: RequestContext, resource_arn: Arn
    ) -> ListTagsForResourceResponse:
        raise NotImplementedError

    @handler("ListTargetsByRule")
    def list_targets_by_rule(
        self,
        context: RequestContext,
        rule: RuleName,
        event_bus_name: EventBusNameOrArn = None,
        next_token: NextToken = None,
        limit: LimitMax100 = None,
    ) -> ListTargetsByRuleResponse:
        raise NotImplementedError

    @handler("PutEvents")
    def put_events(
        self,
        context: RequestContext,
        entries: PutEventsRequestEntryList,
        endpoint_id: EndpointId = None,
    ) -> PutEventsResponse:
        raise NotImplementedError

    @handler("PutPartnerEvents")
    def put_partner_events(
        self, context: RequestContext, entries: PutPartnerEventsRequestEntryList
    ) -> PutPartnerEventsResponse:
        raise NotImplementedError

    @handler("PutPermission")
    def put_permission(
        self,
        context: RequestContext,
        event_bus_name: NonPartnerEventBusName = None,
        action: Action = None,
        principal: Principal = None,
        statement_id: StatementId = None,
        condition: Condition = None,
        policy: String = None,
    ) -> None:
        raise NotImplementedError

    @handler("PutRule")
    def put_rule(
        self,
        context: RequestContext,
        name: RuleName,
        schedule_expression: ScheduleExpression = None,
        event_pattern: EventPattern = None,
        state: RuleState = None,
        description: RuleDescription = None,
        role_arn: RoleArn = None,
        tags: TagList = None,
        event_bus_name: EventBusNameOrArn = None,
    ) -> PutRuleResponse:
        raise NotImplementedError

    @handler("PutTargets")
    def put_targets(
        self,
        context: RequestContext,
        rule: RuleName,
        targets: TargetList,
        event_bus_name: EventBusNameOrArn = None,
    ) -> PutTargetsResponse:
        raise NotImplementedError

    @handler("RemovePermission")
    def remove_permission(
        self,
        context: RequestContext,
        statement_id: StatementId = None,
        remove_all_permissions: Boolean = None,
        event_bus_name: NonPartnerEventBusName = None,
    ) -> None:
        raise NotImplementedError

    @handler("RemoveTargets")
    def remove_targets(
        self,
        context: RequestContext,
        rule: RuleName,
        ids: TargetIdList,
        event_bus_name: EventBusNameOrArn = None,
        force: Boolean = None,
    ) -> RemoveTargetsResponse:
        raise NotImplementedError

    @handler("StartReplay")
    def start_replay(
        self,
        context: RequestContext,
        replay_name: ReplayName,
        event_source_arn: Arn,
        event_start_time: Timestamp,
        event_end_time: Timestamp,
        destination: ReplayDestination,
        description: ReplayDescription = None,
    ) -> StartReplayResponse:
        raise NotImplementedError

    @handler("TagResource")
    def tag_resource(
        self, context: RequestContext, resource_arn: Arn, tags: TagList
    ) -> TagResourceResponse:
        raise NotImplementedError

    @handler("TestEventPattern")
    def test_event_pattern(
        self, context: RequestContext, event_pattern: EventPattern, event: String
    ) -> TestEventPatternResponse:
        raise NotImplementedError

    @handler("UntagResource")
    def untag_resource(
        self, context: RequestContext, resource_arn: Arn, tag_keys: TagKeyList
    ) -> UntagResourceResponse:
        raise NotImplementedError

    @handler("UpdateApiDestination")
    def update_api_destination(
        self,
        context: RequestContext,
        name: ApiDestinationName,
        description: ApiDestinationDescription = None,
        connection_arn: ConnectionArn = None,
        invocation_endpoint: HttpsEndpoint = None,
        http_method: ApiDestinationHttpMethod = None,
        invocation_rate_limit_per_second: ApiDestinationInvocationRateLimitPerSecond = None,
    ) -> UpdateApiDestinationResponse:
        raise NotImplementedError

    @handler("UpdateArchive")
    def update_archive(
        self,
        context: RequestContext,
        archive_name: ArchiveName,
        description: ArchiveDescription = None,
        event_pattern: EventPattern = None,
        retention_days: RetentionDays = None,
    ) -> UpdateArchiveResponse:
        raise NotImplementedError

    @handler("UpdateConnection")
    def update_connection(
        self,
        context: RequestContext,
        name: ConnectionName,
        description: ConnectionDescription = None,
        authorization_type: ConnectionAuthorizationType = None,
        auth_parameters: UpdateConnectionAuthRequestParameters = None,
    ) -> UpdateConnectionResponse:
        raise NotImplementedError

    @handler("UpdateEndpoint")
    def update_endpoint(
        self,
        context: RequestContext,
        name: EndpointName,
        description: EndpointDescription = None,
        routing_config: RoutingConfig = None,
        replication_config: ReplicationConfig = None,
        event_buses: EndpointEventBusList = None,
        role_arn: IamRoleArn = None,
    ) -> UpdateEndpointResponse:
        raise NotImplementedError
