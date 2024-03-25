from datetime import datetime
from typing import Dict, List, Optional, TypedDict

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
    ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS = "ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS"


class ConcurrentModificationException(ServiceException):
    """There is concurrent modification on a rule, target, archive, or replay."""

    code: str = "ConcurrentModificationException"
    sender_fault: bool = False
    status_code: int = 400


class IllegalStatusException(ServiceException):
    """An error occurred because a replay can be canceled only when the state
    is Running or Starting.
    """

    code: str = "IllegalStatusException"
    sender_fault: bool = False
    status_code: int = 400


class InternalException(ServiceException):
    """This exception occurs due to unexpected causes."""

    code: str = "InternalException"
    sender_fault: bool = False
    status_code: int = 400


class InvalidEventPatternException(ServiceException):
    """The event pattern is not valid."""

    code: str = "InvalidEventPatternException"
    sender_fault: bool = False
    status_code: int = 400


class InvalidStateException(ServiceException):
    """The specified state is not a valid state for an event source."""

    code: str = "InvalidStateException"
    sender_fault: bool = False
    status_code: int = 400


class LimitExceededException(ServiceException):
    """The request failed because it attempted to create resource beyond the
    allowed service quota.
    """

    code: str = "LimitExceededException"
    sender_fault: bool = False
    status_code: int = 400


class ManagedRuleException(ServiceException):
    """This rule was created by an Amazon Web Services service on behalf of
    your account. It is managed by that service. If you see this error in
    response to ``DeleteRule`` or ``RemoveTargets``, you can use the
    ``Force`` parameter in those calls to delete the rule or remove targets
    from the rule. You cannot modify these managed rules by using
    ``DisableRule``, ``EnableRule``, ``PutTargets``, ``PutRule``,
    ``TagResource``, or ``UntagResource``.
    """

    code: str = "ManagedRuleException"
    sender_fault: bool = False
    status_code: int = 400


class OperationDisabledException(ServiceException):
    """The operation you are attempting is not available in this region."""

    code: str = "OperationDisabledException"
    sender_fault: bool = False
    status_code: int = 400


class PolicyLengthExceededException(ServiceException):
    """The event bus policy is too long. For more information, see the limits."""

    code: str = "PolicyLengthExceededException"
    sender_fault: bool = False
    status_code: int = 400


class ResourceAlreadyExistsException(ServiceException):
    """The resource you are trying to create already exists."""

    code: str = "ResourceAlreadyExistsException"
    sender_fault: bool = False
    status_code: int = 400


class ResourceNotFoundException(ServiceException):
    """An entity that you specified does not exist."""

    code: str = "ResourceNotFoundException"
    sender_fault: bool = False
    status_code: int = 400


class ActivateEventSourceRequest(ServiceRequest):
    Name: EventSourceName


Timestamp = datetime


class ApiDestination(TypedDict, total=False):
    """Contains details about an API destination."""

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


class AppSyncParameters(TypedDict, total=False):
    """Contains the GraphQL operation to be parsed and executed, if the event
    target is an AppSync API.
    """

    GraphQLOperation: Optional[GraphQLOperation]


Long = int


class Archive(TypedDict, total=False):
    """An ``Archive`` object that contains details about an archive."""

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
    """This structure specifies the VPC subnets and security groups for the
    task, and whether a public IP address is to be used. This structure is
    relevant only for ECS tasks that use the ``awsvpc`` network mode.
    """

    Subnets: StringList
    SecurityGroups: Optional[StringList]
    AssignPublicIp: Optional[AssignPublicIp]


class BatchArrayProperties(TypedDict, total=False):
    """The array properties for the submitted job, such as the size of the
    array. The array size can be between 2 and 10,000. If you specify array
    properties for a job, it becomes an array job. This parameter is used
    only if the target is an Batch job.
    """

    Size: Optional[Integer]


class BatchRetryStrategy(TypedDict, total=False):
    """The retry strategy to use for failed jobs, if the target is an Batch
    job. If you specify a retry strategy here, it overrides the retry
    strategy defined in the job definition.
    """

    Attempts: Optional[Integer]


class BatchParameters(TypedDict, total=False):
    """The custom parameters to be used when the target is an Batch job."""

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
    """The details of a capacity provider strategy. To learn more, see
    `CapacityProviderStrategyItem <https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_CapacityProviderStrategyItem.html>`__
    in the Amazon ECS API Reference.
    """

    capacityProvider: CapacityProvider
    weight: Optional[CapacityProviderStrategyItemWeight]
    base: Optional[CapacityProviderStrategyItemBase]


CapacityProviderStrategy = List[CapacityProviderStrategyItem]


class Condition(TypedDict, total=False):
    """A JSON string which you can use to limit the event bus permissions you
    are granting to only accounts that fulfill the condition. Currently, the
    only supported condition is membership in a certain Amazon Web Services
    organization. The string must contain ``Type``, ``Key``, and ``Value``
    fields. The ``Value`` field specifies the ID of the Amazon Web Services
    organization. Following is an example value for ``Condition``:

    ``'{"Type" : "StringEquals", "Key": "aws:PrincipalOrgID", "Value": "o-1234567890"}'``
    """

    Type: String
    Key: String
    Value: String


class Connection(TypedDict, total=False):
    """Contains information about a connection."""

    ConnectionArn: Optional[ConnectionArn]
    Name: Optional[ConnectionName]
    ConnectionState: Optional[ConnectionState]
    StateReason: Optional[ConnectionStateReason]
    AuthorizationType: Optional[ConnectionAuthorizationType]
    CreationTime: Optional[Timestamp]
    LastModifiedTime: Optional[Timestamp]
    LastAuthorizedTime: Optional[Timestamp]


class ConnectionApiKeyAuthResponseParameters(TypedDict, total=False):
    """Contains the authorization parameters for the connection if API Key is
    specified as the authorization type.
    """

    ApiKeyName: Optional[AuthHeaderParameters]


class ConnectionBodyParameter(TypedDict, total=False):
    """Additional parameter included in the body. You can include up to 100
    additional body parameters per request. An event payload cannot exceed
    64 KB.
    """

    Key: Optional[String]
    Value: Optional[SensitiveString]
    IsValueSecret: Optional[Boolean]


ConnectionBodyParametersList = List[ConnectionBodyParameter]


class ConnectionQueryStringParameter(TypedDict, total=False):
    """Additional query string parameter for the connection. You can include up
    to 100 additional query string parameters per request. Each additional
    parameter counts towards the event payload size, which cannot exceed 64
    KB.
    """

    Key: Optional[QueryStringKey]
    Value: Optional[QueryStringValueSensitive]
    IsValueSecret: Optional[Boolean]


ConnectionQueryStringParametersList = List[ConnectionQueryStringParameter]


class ConnectionHeaderParameter(TypedDict, total=False):
    """Additional parameter included in the header. You can include up to 100
    additional header parameters per request. An event payload cannot exceed
    64 KB.
    """

    Key: Optional[HeaderKey]
    Value: Optional[HeaderValueSensitive]
    IsValueSecret: Optional[Boolean]


ConnectionHeaderParametersList = List[ConnectionHeaderParameter]


class ConnectionHttpParameters(TypedDict, total=False):
    """Contains additional parameters for the connection."""

    HeaderParameters: Optional[ConnectionHeaderParametersList]
    QueryStringParameters: Optional[ConnectionQueryStringParametersList]
    BodyParameters: Optional[ConnectionBodyParametersList]


class ConnectionOAuthClientResponseParameters(TypedDict, total=False):
    """Contains the client response parameters for the connection when OAuth is
    specified as the authorization type.
    """

    ClientID: Optional[AuthHeaderParameters]


class ConnectionOAuthResponseParameters(TypedDict, total=False):
    """Contains the response parameters when OAuth is specified as the
    authorization type.
    """

    ClientParameters: Optional[ConnectionOAuthClientResponseParameters]
    AuthorizationEndpoint: Optional[HttpsEndpoint]
    HttpMethod: Optional[ConnectionOAuthHttpMethod]
    OAuthHttpParameters: Optional[ConnectionHttpParameters]


class ConnectionBasicAuthResponseParameters(TypedDict, total=False):
    """Contains the authorization parameters for the connection if Basic is
    specified as the authorization type.
    """

    Username: Optional[AuthHeaderParameters]


class ConnectionAuthResponseParameters(TypedDict, total=False):
    """Contains the authorization parameters to use for the connection."""

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
    """Contains the API key authorization parameters for the connection."""

    ApiKeyName: AuthHeaderParameters
    ApiKeyValue: AuthHeaderParametersSensitive


class CreateConnectionOAuthClientRequestParameters(TypedDict, total=False):
    """Contains the Basic authorization parameters to use for the connection."""

    ClientID: AuthHeaderParameters
    ClientSecret: AuthHeaderParametersSensitive


class CreateConnectionOAuthRequestParameters(TypedDict, total=False):
    """Contains the OAuth authorization parameters to use for the connection."""

    ClientParameters: CreateConnectionOAuthClientRequestParameters
    AuthorizationEndpoint: HttpsEndpoint
    HttpMethod: ConnectionOAuthHttpMethod
    OAuthHttpParameters: Optional[ConnectionHttpParameters]


class CreateConnectionBasicAuthRequestParameters(TypedDict, total=False):
    """Contains the Basic authorization parameters to use for the connection."""

    Username: AuthHeaderParameters
    Password: AuthHeaderParametersSensitive


class CreateConnectionAuthRequestParameters(TypedDict, total=False):
    """Contains the authorization parameters for the connection."""

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
    """The event buses the endpoint is associated with."""

    EventBusArn: NonPartnerEventBusArn


EndpointEventBusList = List[EndpointEventBus]


class ReplicationConfig(TypedDict, total=False):
    """Endpoints can replicate all events to the secondary Region."""

    State: Optional[ReplicationState]


class Secondary(TypedDict, total=False):
    """The secondary Region that processes events when failover is triggered or
    replication is enabled.
    """

    Route: Route


class Primary(TypedDict, total=False):
    """The primary Region of the endpoint."""

    HealthCheck: HealthCheck


class FailoverConfig(TypedDict, total=False):
    """The failover configuration for an endpoint. This includes what triggers
    failover and what happens when it's triggered.
    """

    Primary: Primary
    Secondary: Secondary


class RoutingConfig(TypedDict, total=False):
    """The routing configuration of the endpoint."""

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
    """A key-value pair associated with an Amazon Web Services resource. In
    EventBridge, rules and event buses support tagging.
    """

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
    """A ``DeadLetterConfig`` object that contains information about a
    dead-letter queue configuration.
    """

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
    """A ``ReplayDestination`` object that contains details about a replay."""

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
    """This structure specifies the network configuration for an ECS task."""

    awsvpcConfiguration: Optional[AwsVpcConfiguration]


class EcsParameters(TypedDict, total=False):
    """The custom parameters to be used when the target is an Amazon ECS task."""

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
    """A global endpoint used to improve your application's availability by
    making it regional-fault tolerant. For more information about global
    endpoints, see `Making applications Regional-fault tolerant with global
    endpoints and event
    replication <https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-global-endpoints.html>`__
    in the *Amazon EventBridge User Guide*.
    """

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
    """An event bus receives events from a source, uses rules to evaluate them,
    applies any configured input transformation, and routes them to the
    appropriate target(s). Your account's default event bus receives events
    from Amazon Web Services services. A custom event bus can receive events
    from your custom applications and services. A partner event bus receives
    events from an event source created by an SaaS partner. These events
    come from the partners services or applications.
    """

    Name: Optional[String]
    Arn: Optional[String]
    Policy: Optional[String]


EventBusList = List[EventBus]
EventResourceList = List[EventResource]


class EventSource(TypedDict, total=False):
    """A partner event source is created by an SaaS partner. If a customer
    creates a partner event bus that matches this event source, that Amazon
    Web Services account can receive events from the partner's applications
    or services.
    """

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
    """These are custom parameter to be used when the target is an API Gateway
    APIs or EventBridge ApiDestinations. In the latter case, these are
    merged with any InvocationParameters specified on the Connection, with
    any values from the Connection taking precedence.
    """

    PathParameterValues: Optional[PathParameterList]
    HeaderParameters: Optional[HeaderParametersMap]
    QueryStringParameters: Optional[QueryStringParametersMap]


TransformerPaths = Dict[InputTransformerPathKey, TargetInputPath]


class InputTransformer(TypedDict, total=False):
    """Contains the parameters needed for you to provide custom input to a
    target based on one or more pieces of data extracted from the event.
    """

    InputPathsMap: Optional[TransformerPaths]
    InputTemplate: TransformerInput


class KinesisParameters(TypedDict, total=False):
    """This object enables you to specify a JSON path to extract from the event
    and use as the partition key for the Amazon Kinesis data stream, so that
    you can control the shard to which the event goes. If you do not include
    this parameter, the default is to use the ``eventId`` as the partition
    key.
    """

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
    """The Amazon Web Services account that a partner event source has been
    offered to.
    """

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
    """A partner event source is created by an SaaS partner. If a customer
    creates a partner event bus that matches this event source, that Amazon
    Web Services account can receive events from the partner's applications
    or services.
    """

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
    """A ``Replay`` object that contains details about a replay."""

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
    """Contains information about a rule in Amazon EventBridge."""

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
    """A ``RetryPolicy`` object that includes information about the retry
    policy settings.
    """

    MaximumRetryAttempts: Optional[MaximumRetryAttempts]
    MaximumEventAgeInSeconds: Optional[MaximumEventAgeInSeconds]


class SageMakerPipelineParameter(TypedDict, total=False):
    """Name/Value pair of a parameter to start execution of a SageMaker Model
    Building Pipeline.
    """

    Name: SageMakerPipelineParameterName
    Value: SageMakerPipelineParameterValue


SageMakerPipelineParameterList = List[SageMakerPipelineParameter]


class SageMakerPipelineParameters(TypedDict, total=False):
    """These are custom parameters to use when the target is a SageMaker Model
    Building Pipeline that starts based on EventBridge events.
    """

    PipelineParameterList: Optional[SageMakerPipelineParameterList]


Sqls = List[Sql]


class RedshiftDataParameters(TypedDict, total=False):
    """These are custom parameters to be used when the target is a Amazon
    Redshift cluster to invoke the Amazon Redshift Data API ExecuteStatement
    based on EventBridge events.
    """

    SecretManagerArn: Optional[RedshiftSecretManagerArn]
    Database: Database
    DbUser: Optional[DbUser]
    Sql: Optional[Sql]
    StatementName: Optional[StatementName]
    WithEvent: Optional[Boolean]
    Sqls: Optional[Sqls]


class SqsParameters(TypedDict, total=False):
    """This structure includes the custom parameter to be used when the target
    is an SQS FIFO queue.
    """

    MessageGroupId: Optional[MessageGroupId]


RunCommandTargetValues = List[RunCommandTargetValue]


class RunCommandTarget(TypedDict, total=False):
    """Information about the EC2 instances that are to be sent the command,
    specified as key-value pairs. Each ``RunCommandTarget`` block can
    include only one key, but this key may specify multiple values.
    """

    Key: RunCommandTargetKey
    Values: RunCommandTargetValues


RunCommandTargets = List[RunCommandTarget]


class RunCommandParameters(TypedDict, total=False):
    """This parameter contains the criteria (either InstanceIds or a tag) used
    to specify which EC2 instances are to be sent the command.
    """

    RunCommandTargets: RunCommandTargets


class Target(TypedDict, total=False):
    """Targets are the resources to be invoked when a rule is triggered. For a
    complete list of services and resources that can be set as a target, see
    `PutTargets <https://docs.aws.amazon.com/eventbridge/latest/APIReference/API_PutTargets.html>`__.

    If you are setting the event bus of another account as the target, and
    that account granted permission to your account through an organization
    instead of directly by the account ID, then you must specify a
    ``RoleArn`` with proper permissions in the ``Target`` structure. For
    more information, see `Sending and Receiving Events Between Amazon Web
    Services
    Accounts <https://docs.aws.amazon.com/eventbridge/latest/userguide/eventbridge-cross-account-event-delivery.html>`__
    in the *Amazon EventBridge User Guide*.
    """

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
    AppSyncParameters: Optional[AppSyncParameters]


TargetList = List[Target]


class ListTargetsByRuleResponse(TypedDict, total=False):
    Targets: Optional[TargetList]
    NextToken: Optional[NextToken]


class PutEventsRequestEntry(TypedDict, total=False):
    """Represents an event to be submitted."""

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
    """Represents the results of an event submitted to an event bus.

    If the submission was successful, the entry has the event ID in it.
    Otherwise, you can use the error code and error message to identify the
    problem with the entry.

    For information about the errors that are common to all actions, see
    `Common
    Errors <https://docs.aws.amazon.com/eventbridge/latest/APIReference/CommonErrors.html>`__.
    """

    EventId: Optional[EventId]
    ErrorCode: Optional[ErrorCode]
    ErrorMessage: Optional[ErrorMessage]


PutEventsResultEntryList = List[PutEventsResultEntry]


class PutEventsResponse(TypedDict, total=False):
    FailedEntryCount: Optional[Integer]
    Entries: Optional[PutEventsResultEntryList]


class PutPartnerEventsRequestEntry(TypedDict, total=False):
    """The details about an event generated by an SaaS partner."""

    Time: Optional[EventTime]
    Source: Optional[EventSourceName]
    Resources: Optional[EventResourceList]
    DetailType: Optional[String]
    Detail: Optional[String]


PutPartnerEventsRequestEntryList = List[PutPartnerEventsRequestEntry]


class PutPartnerEventsRequest(ServiceRequest):
    Entries: PutPartnerEventsRequestEntryList


class PutPartnerEventsResultEntry(TypedDict, total=False):
    """The result of an event entry the partner submitted in this request. If
    the event was successfully submitted, the entry has the event ID in it.
    Otherwise, you can use the error code and error message to identify the
    problem with the entry.
    """

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
    """Represents a target that failed to be added to a rule."""

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
    """Represents a target that failed to be removed from a rule."""

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
    """Contains the API key authorization parameters to use to update the
    connection.
    """

    ApiKeyName: Optional[AuthHeaderParameters]
    ApiKeyValue: Optional[AuthHeaderParametersSensitive]


class UpdateConnectionOAuthClientRequestParameters(TypedDict, total=False):
    """Contains the OAuth authorization parameters to use for the connection."""

    ClientID: Optional[AuthHeaderParameters]
    ClientSecret: Optional[AuthHeaderParametersSensitive]


class UpdateConnectionOAuthRequestParameters(TypedDict, total=False):
    """Contains the OAuth request parameters to use for the connection."""

    ClientParameters: Optional[UpdateConnectionOAuthClientRequestParameters]
    AuthorizationEndpoint: Optional[HttpsEndpoint]
    HttpMethod: Optional[ConnectionOAuthHttpMethod]
    OAuthHttpParameters: Optional[ConnectionHttpParameters]


class UpdateConnectionBasicAuthRequestParameters(TypedDict, total=False):
    """Contains the Basic authorization parameters for the connection."""

    Username: Optional[AuthHeaderParameters]
    Password: Optional[AuthHeaderParametersSensitive]


class UpdateConnectionAuthRequestParameters(TypedDict, total=False):
    """Contains the additional parameters to use for the connection."""

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
    def activate_event_source(
        self, context: RequestContext, name: EventSourceName, **kwargs
    ) -> None:
        """Activates a partner event source that has been deactivated. Once
        activated, your matching event bus will start receiving events from the
        event source.

        :param name: The name of the partner event source to activate.
        :raises ResourceNotFoundException:
        :raises ConcurrentModificationException:
        :raises InvalidStateException:
        :raises InternalException:
        :raises OperationDisabledException:
        """
        raise NotImplementedError

    @handler("CancelReplay")
    def cancel_replay(
        self, context: RequestContext, replay_name: ReplayName, **kwargs
    ) -> CancelReplayResponse:
        """Cancels the specified replay.

        :param replay_name: The name of the replay to cancel.
        :returns: CancelReplayResponse
        :raises ResourceNotFoundException:
        :raises ConcurrentModificationException:
        :raises IllegalStatusException:
        :raises InternalException:
        """
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
        **kwargs,
    ) -> CreateApiDestinationResponse:
        """Creates an API destination, which is an HTTP invocation endpoint
        configured as a target for events.

        API destinations do not support private destinations, such as interface
        VPC endpoints.

        For more information, see `API
        destinations <https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-api-destinations.html>`__
        in the *EventBridge User Guide*.

        :param name: The name for the API destination to create.
        :param connection_arn: The ARN of the connection to use for the API destination.
        :param invocation_endpoint: The URL to the HTTP invocation endpoint for the API destination.
        :param http_method: The method to use for the request to the HTTP invocation endpoint.
        :param description: A description for the API destination to create.
        :param invocation_rate_limit_per_second: The maximum number of requests per second to send to the HTTP invocation
        endpoint.
        :returns: CreateApiDestinationResponse
        :raises ResourceAlreadyExistsException:
        :raises ResourceNotFoundException:
        :raises LimitExceededException:
        :raises InternalException:
        """
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
        **kwargs,
    ) -> CreateArchiveResponse:
        """Creates an archive of events with the specified settings. When you
        create an archive, incoming events might not immediately start being
        sent to the archive. Allow a short period of time for changes to take
        effect. If you do not specify a pattern to filter events sent to the
        archive, all events are sent to the archive except replayed events.
        Replayed events are not sent to an archive.

        :param archive_name: The name for the archive to create.
        :param event_source_arn: The ARN of the event bus that sends events to the archive.
        :param description: A description for the archive.
        :param event_pattern: An event pattern to use to filter events sent to the archive.
        :param retention_days: The number of days to retain events for.
        :returns: CreateArchiveResponse
        :raises ConcurrentModificationException:
        :raises ResourceAlreadyExistsException:
        :raises ResourceNotFoundException:
        :raises InternalException:
        :raises LimitExceededException:
        :raises InvalidEventPatternException:
        """
        raise NotImplementedError

    @handler("CreateConnection")
    def create_connection(
        self,
        context: RequestContext,
        name: ConnectionName,
        authorization_type: ConnectionAuthorizationType,
        auth_parameters: CreateConnectionAuthRequestParameters,
        description: ConnectionDescription = None,
        **kwargs,
    ) -> CreateConnectionResponse:
        """Creates a connection. A connection defines the authorization type and
        credentials to use for authorization with an API destination HTTP
        endpoint.

        :param name: The name for the connection to create.
        :param authorization_type: The type of authorization to use for the connection.
        :param auth_parameters: A ``CreateConnectionAuthRequestParameters`` object that contains the
        authorization parameters to use to authorize with the endpoint.
        :param description: A description for the connection to create.
        :returns: CreateConnectionResponse
        :raises ResourceAlreadyExistsException:
        :raises LimitExceededException:
        :raises InternalException:
        """
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
        **kwargs,
    ) -> CreateEndpointResponse:
        """Creates a global endpoint. Global endpoints improve your application's
        availability by making it regional-fault tolerant. To do this, you
        define a primary and secondary Region with event buses in each Region.
        You also create a Amazon Route 53 health check that will tell
        EventBridge to route events to the secondary Region when an "unhealthy"
        state is encountered and events will be routed back to the primary
        Region when the health check reports a "healthy" state.

        :param name: The name of the global endpoint.
        :param routing_config: Configure the routing policy, including the health check and secondary
        Region.
        :param event_buses: Define the event buses used.
        :param description: A description of the global endpoint.
        :param replication_config: Enable or disable event replication.
        :param role_arn: The ARN of the role used for replication.
        :returns: CreateEndpointResponse
        :raises ResourceAlreadyExistsException:
        :raises LimitExceededException:
        :raises InternalException:
        """
        raise NotImplementedError

    @handler("CreateEventBus")
    def create_event_bus(
        self,
        context: RequestContext,
        name: EventBusName,
        event_source_name: EventSourceName = None,
        tags: TagList = None,
        **kwargs,
    ) -> CreateEventBusResponse:
        """Creates a new event bus within your account. This can be a custom event
        bus which you can use to receive events from your custom applications
        and services, or it can be a partner event bus which can be matched to a
        partner event source.

        :param name: The name of the new event bus.
        :param event_source_name: If you are creating a partner event bus, this specifies the partner
        event source that the new event bus will be matched with.
        :param tags: Tags to associate with the event bus.
        :returns: CreateEventBusResponse
        :raises ResourceAlreadyExistsException:
        :raises ResourceNotFoundException:
        :raises InvalidStateException:
        :raises InternalException:
        :raises ConcurrentModificationException:
        :raises LimitExceededException:
        :raises OperationDisabledException:
        """
        raise NotImplementedError

    @handler("CreatePartnerEventSource")
    def create_partner_event_source(
        self,
        context: RequestContext,
        name: EventSourceName,
        account: AccountId,
        **kwargs,
    ) -> CreatePartnerEventSourceResponse:
        """Called by an SaaS partner to create a partner event source. This
        operation is not used by Amazon Web Services customers.

        Each partner event source can be used by one Amazon Web Services account
        to create a matching partner event bus in that Amazon Web Services
        account. A SaaS partner must create one partner event source for each
        Amazon Web Services account that wants to receive those event types.

        A partner event source creates events based on resources within the SaaS
        partner's service or application.

        An Amazon Web Services account that creates a partner event bus that
        matches the partner event source can use that event bus to receive
        events from the partner, and then process them using Amazon Web Services
        Events rules and targets.

        Partner event source names follow this format:

        ```` *``partner_name``* ``/`` *``event_namespace``* ``/`` *``event_name``* ````

        -  *partner_name* is determined during partner registration, and
           identifies the partner to Amazon Web Services customers.

        -  *event_namespace* is determined by the partner, and is a way for the
           partner to categorize their events.

        -  *event_name* is determined by the partner, and should uniquely
           identify an event-generating resource within the partner system.

           The *event_name* must be unique across all Amazon Web Services
           customers. This is because the event source is a shared resource
           between the partner and customer accounts, and each partner event
           source unique in the partner account.

        The combination of *event_namespace* and *event_name* should help Amazon
        Web Services customers decide whether to create an event bus to receive
        these events.

        :param name: The name of the partner event source.
        :param account: The Amazon Web Services account ID that is permitted to create a
        matching partner event bus for this partner event source.
        :returns: CreatePartnerEventSourceResponse
        :raises ResourceAlreadyExistsException:
        :raises InternalException:
        :raises ConcurrentModificationException:
        :raises LimitExceededException:
        :raises OperationDisabledException:
        """
        raise NotImplementedError

    @handler("DeactivateEventSource")
    def deactivate_event_source(
        self, context: RequestContext, name: EventSourceName, **kwargs
    ) -> None:
        """You can use this operation to temporarily stop receiving events from the
        specified partner event source. The matching event bus is not deleted.

        When you deactivate a partner event source, the source goes into PENDING
        state. If it remains in PENDING state for more than two weeks, it is
        deleted.

        To activate a deactivated partner event source, use
        `ActivateEventSource <https://docs.aws.amazon.com/eventbridge/latest/APIReference/API_ActivateEventSource.html>`__.

        :param name: The name of the partner event source to deactivate.
        :raises ResourceNotFoundException:
        :raises ConcurrentModificationException:
        :raises InvalidStateException:
        :raises InternalException:
        :raises OperationDisabledException:
        """
        raise NotImplementedError

    @handler("DeauthorizeConnection")
    def deauthorize_connection(
        self, context: RequestContext, name: ConnectionName, **kwargs
    ) -> DeauthorizeConnectionResponse:
        """Removes all authorization parameters from the connection. This lets you
        remove the secret from the connection so you can reuse it without having
        to create a new connection.

        :param name: The name of the connection to remove authorization from.
        :returns: DeauthorizeConnectionResponse
        :raises ConcurrentModificationException:
        :raises ResourceNotFoundException:
        :raises InternalException:
        """
        raise NotImplementedError

    @handler("DeleteApiDestination")
    def delete_api_destination(
        self, context: RequestContext, name: ApiDestinationName, **kwargs
    ) -> DeleteApiDestinationResponse:
        """Deletes the specified API destination.

        :param name: The name of the destination to delete.
        :returns: DeleteApiDestinationResponse
        :raises ConcurrentModificationException:
        :raises ResourceNotFoundException:
        :raises InternalException:
        """
        raise NotImplementedError

    @handler("DeleteArchive")
    def delete_archive(
        self, context: RequestContext, archive_name: ArchiveName, **kwargs
    ) -> DeleteArchiveResponse:
        """Deletes the specified archive.

        :param archive_name: The name of the archive to delete.
        :returns: DeleteArchiveResponse
        :raises ConcurrentModificationException:
        :raises ResourceNotFoundException:
        :raises InternalException:
        """
        raise NotImplementedError

    @handler("DeleteConnection")
    def delete_connection(
        self, context: RequestContext, name: ConnectionName, **kwargs
    ) -> DeleteConnectionResponse:
        """Deletes a connection.

        :param name: The name of the connection to delete.
        :returns: DeleteConnectionResponse
        :raises ConcurrentModificationException:
        :raises ResourceNotFoundException:
        :raises InternalException:
        """
        raise NotImplementedError

    @handler("DeleteEndpoint")
    def delete_endpoint(
        self, context: RequestContext, name: EndpointName, **kwargs
    ) -> DeleteEndpointResponse:
        """Delete an existing global endpoint. For more information about global
        endpoints, see `Making applications Regional-fault tolerant with global
        endpoints and event
        replication <https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-global-endpoints.html>`__
        in the *Amazon EventBridge User Guide*.

        :param name: The name of the endpoint you want to delete.
        :returns: DeleteEndpointResponse
        :raises ConcurrentModificationException:
        :raises ResourceNotFoundException:
        :raises InternalException:
        """
        raise NotImplementedError

    @handler("DeleteEventBus")
    def delete_event_bus(self, context: RequestContext, name: EventBusName, **kwargs) -> None:
        """Deletes the specified custom event bus or partner event bus. All rules
        associated with this event bus need to be deleted. You can't delete your
        account's default event bus.

        :param name: The name of the event bus to delete.
        :raises InternalException:
        :raises ConcurrentModificationException:
        """
        raise NotImplementedError

    @handler("DeletePartnerEventSource")
    def delete_partner_event_source(
        self,
        context: RequestContext,
        name: EventSourceName,
        account: AccountId,
        **kwargs,
    ) -> None:
        """This operation is used by SaaS partners to delete a partner event
        source. This operation is not used by Amazon Web Services customers.

        When you delete an event source, the status of the corresponding partner
        event bus in the Amazon Web Services customer account becomes DELETED.

        :param name: The name of the event source to delete.
        :param account: The Amazon Web Services account ID of the Amazon Web Services customer
        that the event source was created for.
        :raises InternalException:
        :raises ConcurrentModificationException:
        :raises OperationDisabledException:
        """
        raise NotImplementedError

    @handler("DeleteRule")
    def delete_rule(
        self,
        context: RequestContext,
        name: RuleName,
        event_bus_name: EventBusNameOrArn = None,
        force: Boolean = None,
        **kwargs,
    ) -> None:
        """Deletes the specified rule.

        Before you can delete the rule, you must remove all targets, using
        `RemoveTargets <https://docs.aws.amazon.com/eventbridge/latest/APIReference/API_RemoveTargets.html>`__.

        When you delete a rule, incoming events might continue to match to the
        deleted rule. Allow a short period of time for changes to take effect.

        If you call delete rule multiple times for the same rule, all calls will
        succeed. When you call delete rule for a non-existent custom eventbus,
        ``ResourceNotFoundException`` is returned.

        Managed rules are rules created and managed by another Amazon Web
        Services service on your behalf. These rules are created by those other
        Amazon Web Services services to support functionality in those services.
        You can delete these rules using the ``Force`` option, but you should do
        so only if you are sure the other service is not still using that rule.

        :param name: The name of the rule.
        :param event_bus_name: The name or ARN of the event bus associated with the rule.
        :param force: If this is a managed rule, created by an Amazon Web Services service on
        your behalf, you must specify ``Force`` as ``True`` to delete the rule.
        :raises ConcurrentModificationException:
        :raises ManagedRuleException:
        :raises InternalException:
        :raises ResourceNotFoundException:
        """
        raise NotImplementedError

    @handler("DescribeApiDestination")
    def describe_api_destination(
        self, context: RequestContext, name: ApiDestinationName, **kwargs
    ) -> DescribeApiDestinationResponse:
        """Retrieves details about an API destination.

        :param name: The name of the API destination to retrieve.
        :returns: DescribeApiDestinationResponse
        :raises ResourceNotFoundException:
        :raises InternalException:
        """
        raise NotImplementedError

    @handler("DescribeArchive")
    def describe_archive(
        self, context: RequestContext, archive_name: ArchiveName, **kwargs
    ) -> DescribeArchiveResponse:
        """Retrieves details about an archive.

        :param archive_name: The name of the archive to retrieve.
        :returns: DescribeArchiveResponse
        :raises ResourceAlreadyExistsException:
        :raises ResourceNotFoundException:
        :raises InternalException:
        """
        raise NotImplementedError

    @handler("DescribeConnection")
    def describe_connection(
        self, context: RequestContext, name: ConnectionName, **kwargs
    ) -> DescribeConnectionResponse:
        """Retrieves details about a connection.

        :param name: The name of the connection to retrieve.
        :returns: DescribeConnectionResponse
        :raises ResourceNotFoundException:
        :raises InternalException:
        """
        raise NotImplementedError

    @handler("DescribeEndpoint")
    def describe_endpoint(
        self,
        context: RequestContext,
        name: EndpointName,
        home_region: HomeRegion = None,
        **kwargs,
    ) -> DescribeEndpointResponse:
        """Get the information about an existing global endpoint. For more
        information about global endpoints, see `Making applications
        Regional-fault tolerant with global endpoints and event
        replication <https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-global-endpoints.html>`__
        in the *Amazon EventBridge User Guide*.

        :param name: The name of the endpoint you want to get information about.
        :param home_region: The primary Region of the endpoint you want to get information about.
        :returns: DescribeEndpointResponse
        :raises ResourceNotFoundException:
        :raises InternalException:
        """
        raise NotImplementedError

    @handler("DescribeEventBus")
    def describe_event_bus(
        self, context: RequestContext, name: EventBusNameOrArn = None, **kwargs
    ) -> DescribeEventBusResponse:
        """Displays details about an event bus in your account. This can include
        the external Amazon Web Services accounts that are permitted to write
        events to your default event bus, and the associated policy. For custom
        event buses and partner event buses, it displays the name, ARN, policy,
        state, and creation time.

        To enable your account to receive events from other accounts on its
        default event bus, use
        `PutPermission <https://docs.aws.amazon.com/eventbridge/latest/APIReference/API_PutPermission.html>`__.

        For more information about partner event buses, see
        `CreateEventBus <https://docs.aws.amazon.com/eventbridge/latest/APIReference/API_CreateEventBus.html>`__.

        :param name: The name or ARN of the event bus to show details for.
        :returns: DescribeEventBusResponse
        :raises ResourceNotFoundException:
        :raises InternalException:
        """
        raise NotImplementedError

    @handler("DescribeEventSource")
    def describe_event_source(
        self, context: RequestContext, name: EventSourceName, **kwargs
    ) -> DescribeEventSourceResponse:
        """This operation lists details about a partner event source that is shared
        with your account.

        :param name: The name of the partner event source to display the details of.
        :returns: DescribeEventSourceResponse
        :raises ResourceNotFoundException:
        :raises InternalException:
        :raises OperationDisabledException:
        """
        raise NotImplementedError

    @handler("DescribePartnerEventSource")
    def describe_partner_event_source(
        self, context: RequestContext, name: EventSourceName, **kwargs
    ) -> DescribePartnerEventSourceResponse:
        """An SaaS partner can use this operation to list details about a partner
        event source that they have created. Amazon Web Services customers do
        not use this operation. Instead, Amazon Web Services customers can use
        `DescribeEventSource <https://docs.aws.amazon.com/eventbridge/latest/APIReference/API_DescribeEventSource.html>`__
        to see details about a partner event source that is shared with them.

        :param name: The name of the event source to display.
        :returns: DescribePartnerEventSourceResponse
        :raises ResourceNotFoundException:
        :raises InternalException:
        :raises OperationDisabledException:
        """
        raise NotImplementedError

    @handler("DescribeReplay")
    def describe_replay(
        self, context: RequestContext, replay_name: ReplayName, **kwargs
    ) -> DescribeReplayResponse:
        """Retrieves details about a replay. Use ``DescribeReplay`` to determine
        the progress of a running replay. A replay processes events to replay
        based on the time in the event, and replays them using 1 minute
        intervals. If you use ``StartReplay`` and specify an ``EventStartTime``
        and an ``EventEndTime`` that covers a 20 minute time range, the events
        are replayed from the first minute of that 20 minute range first. Then
        the events from the second minute are replayed. You can use
        ``DescribeReplay`` to determine the progress of a replay. The value
        returned for ``EventLastReplayedTime`` indicates the time within the
        specified time range associated with the last event replayed.

        :param replay_name: The name of the replay to retrieve.
        :returns: DescribeReplayResponse
        :raises ResourceNotFoundException:
        :raises InternalException:
        """
        raise NotImplementedError

    @handler("DescribeRule")
    def describe_rule(
        self,
        context: RequestContext,
        name: RuleName,
        event_bus_name: EventBusNameOrArn = None,
        **kwargs,
    ) -> DescribeRuleResponse:
        """Describes the specified rule.

        DescribeRule does not list the targets of a rule. To see the targets
        associated with a rule, use
        `ListTargetsByRule <https://docs.aws.amazon.com/eventbridge/latest/APIReference/API_ListTargetsByRule.html>`__.

        :param name: The name of the rule.
        :param event_bus_name: The name or ARN of the event bus associated with the rule.
        :returns: DescribeRuleResponse
        :raises ResourceNotFoundException:
        :raises InternalException:
        """
        raise NotImplementedError

    @handler("DisableRule")
    def disable_rule(
        self,
        context: RequestContext,
        name: RuleName,
        event_bus_name: EventBusNameOrArn = None,
        **kwargs,
    ) -> None:
        """Disables the specified rule. A disabled rule won't match any events, and
        won't self-trigger if it has a schedule expression.

        When you disable a rule, incoming events might continue to match to the
        disabled rule. Allow a short period of time for changes to take effect.

        :param name: The name of the rule.
        :param event_bus_name: The name or ARN of the event bus associated with the rule.
        :raises ResourceNotFoundException:
        :raises ConcurrentModificationException:
        :raises ManagedRuleException:
        :raises InternalException:
        """
        raise NotImplementedError

    @handler("EnableRule")
    def enable_rule(
        self,
        context: RequestContext,
        name: RuleName,
        event_bus_name: EventBusNameOrArn = None,
        **kwargs,
    ) -> None:
        """Enables the specified rule. If the rule does not exist, the operation
        fails.

        When you enable a rule, incoming events might not immediately start
        matching to a newly enabled rule. Allow a short period of time for
        changes to take effect.

        :param name: The name of the rule.
        :param event_bus_name: The name or ARN of the event bus associated with the rule.
        :raises ResourceNotFoundException:
        :raises ConcurrentModificationException:
        :raises ManagedRuleException:
        :raises InternalException:
        """
        raise NotImplementedError

    @handler("ListApiDestinations")
    def list_api_destinations(
        self,
        context: RequestContext,
        name_prefix: ApiDestinationName = None,
        connection_arn: ConnectionArn = None,
        next_token: NextToken = None,
        limit: LimitMax100 = None,
        **kwargs,
    ) -> ListApiDestinationsResponse:
        """Retrieves a list of API destination in the account in the current
        Region.

        :param name_prefix: A name prefix to filter results returned.
        :param connection_arn: The ARN of the connection specified for the API destination.
        :param next_token: The token returned by a previous call to retrieve the next set of
        results.
        :param limit: The maximum number of API destinations to include in the response.
        :returns: ListApiDestinationsResponse
        :raises InternalException:
        """
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
        **kwargs,
    ) -> ListArchivesResponse:
        """Lists your archives. You can either list all the archives or you can
        provide a prefix to match to the archive names. Filter parameters are
        exclusive.

        :param name_prefix: A name prefix to filter the archives returned.
        :param event_source_arn: The ARN of the event source associated with the archive.
        :param state: The state of the archive.
        :param next_token: The token returned by a previous call to retrieve the next set of
        results.
        :param limit: The maximum number of results to return.
        :returns: ListArchivesResponse
        :raises ResourceNotFoundException:
        :raises InternalException:
        """
        raise NotImplementedError

    @handler("ListConnections")
    def list_connections(
        self,
        context: RequestContext,
        name_prefix: ConnectionName = None,
        connection_state: ConnectionState = None,
        next_token: NextToken = None,
        limit: LimitMax100 = None,
        **kwargs,
    ) -> ListConnectionsResponse:
        """Retrieves a list of connections from the account.

        :param name_prefix: A name prefix to filter results returned.
        :param connection_state: The state of the connection.
        :param next_token: The token returned by a previous call to retrieve the next set of
        results.
        :param limit: The maximum number of connections to return.
        :returns: ListConnectionsResponse
        :raises InternalException:
        """
        raise NotImplementedError

    @handler("ListEndpoints")
    def list_endpoints(
        self,
        context: RequestContext,
        name_prefix: EndpointName = None,
        home_region: HomeRegion = None,
        next_token: NextToken = None,
        max_results: LimitMax100 = None,
        **kwargs,
    ) -> ListEndpointsResponse:
        """List the global endpoints associated with this account. For more
        information about global endpoints, see `Making applications
        Regional-fault tolerant with global endpoints and event
        replication <https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-global-endpoints.html>`__
        in the *Amazon EventBridge User Guide*.

        :param name_prefix: A value that will return a subset of the endpoints associated with this
        account.
        :param home_region: The primary Region of the endpoints associated with this account.
        :param next_token: If ``nextToken`` is returned, there are more results available.
        :param max_results: The maximum number of results returned by the call.
        :returns: ListEndpointsResponse
        :raises InternalException:
        """
        raise NotImplementedError

    @handler("ListEventBuses")
    def list_event_buses(
        self,
        context: RequestContext,
        name_prefix: EventBusName = None,
        next_token: NextToken = None,
        limit: LimitMax100 = None,
        **kwargs,
    ) -> ListEventBusesResponse:
        """Lists all the event buses in your account, including the default event
        bus, custom event buses, and partner event buses.

        :param name_prefix: Specifying this limits the results to only those event buses with names
        that start with the specified prefix.
        :param next_token: The token returned by a previous call to retrieve the next set of
        results.
        :param limit: Specifying this limits the number of results returned by this operation.
        :returns: ListEventBusesResponse
        :raises InternalException:
        """
        raise NotImplementedError

    @handler("ListEventSources")
    def list_event_sources(
        self,
        context: RequestContext,
        name_prefix: EventSourceNamePrefix = None,
        next_token: NextToken = None,
        limit: LimitMax100 = None,
        **kwargs,
    ) -> ListEventSourcesResponse:
        """You can use this to see all the partner event sources that have been
        shared with your Amazon Web Services account. For more information about
        partner event sources, see
        `CreateEventBus <https://docs.aws.amazon.com/eventbridge/latest/APIReference/API_CreateEventBus.html>`__.

        :param name_prefix: Specifying this limits the results to only those partner event sources
        with names that start with the specified prefix.
        :param next_token: The token returned by a previous call to retrieve the next set of
        results.
        :param limit: Specifying this limits the number of results returned by this operation.
        :returns: ListEventSourcesResponse
        :raises InternalException:
        :raises OperationDisabledException:
        """
        raise NotImplementedError

    @handler("ListPartnerEventSourceAccounts")
    def list_partner_event_source_accounts(
        self,
        context: RequestContext,
        event_source_name: EventSourceName,
        next_token: NextToken = None,
        limit: LimitMax100 = None,
        **kwargs,
    ) -> ListPartnerEventSourceAccountsResponse:
        """An SaaS partner can use this operation to display the Amazon Web
        Services account ID that a particular partner event source name is
        associated with. This operation is not used by Amazon Web Services
        customers.

        :param event_source_name: The name of the partner event source to display account information
        about.
        :param next_token: The token returned by a previous call to this operation.
        :param limit: Specifying this limits the number of results returned by this operation.
        :returns: ListPartnerEventSourceAccountsResponse
        :raises ResourceNotFoundException:
        :raises InternalException:
        :raises OperationDisabledException:
        """
        raise NotImplementedError

    @handler("ListPartnerEventSources")
    def list_partner_event_sources(
        self,
        context: RequestContext,
        name_prefix: PartnerEventSourceNamePrefix,
        next_token: NextToken = None,
        limit: LimitMax100 = None,
        **kwargs,
    ) -> ListPartnerEventSourcesResponse:
        """An SaaS partner can use this operation to list all the partner event
        source names that they have created. This operation is not used by
        Amazon Web Services customers.

        :param name_prefix: If you specify this, the results are limited to only those partner event
        sources that start with the string you specify.
        :param next_token: The token returned by a previous call to this operation.
        :param limit: pecifying this limits the number of results returned by this operation.
        :returns: ListPartnerEventSourcesResponse
        :raises InternalException:
        :raises OperationDisabledException:
        """
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
        **kwargs,
    ) -> ListReplaysResponse:
        """Lists your replays. You can either list all the replays or you can
        provide a prefix to match to the replay names. Filter parameters are
        exclusive.

        :param name_prefix: A name prefix to filter the replays returned.
        :param state: The state of the replay.
        :param event_source_arn: The ARN of the archive from which the events are replayed.
        :param next_token: The token returned by a previous call to retrieve the next set of
        results.
        :param limit: The maximum number of replays to retrieve.
        :returns: ListReplaysResponse
        :raises InternalException:
        """
        raise NotImplementedError

    @handler("ListRuleNamesByTarget")
    def list_rule_names_by_target(
        self,
        context: RequestContext,
        target_arn: TargetArn,
        event_bus_name: EventBusNameOrArn = None,
        next_token: NextToken = None,
        limit: LimitMax100 = None,
        **kwargs,
    ) -> ListRuleNamesByTargetResponse:
        """Lists the rules for the specified target. You can see which of the rules
        in Amazon EventBridge can invoke a specific target in your account.

        The maximum number of results per page for requests is 100.

        :param target_arn: The Amazon Resource Name (ARN) of the target resource.
        :param event_bus_name: The name or ARN of the event bus to list rules for.
        :param next_token: The token returned by a previous call to retrieve the next set of
        results.
        :param limit: The maximum number of results to return.
        :returns: ListRuleNamesByTargetResponse
        :raises InternalException:
        :raises ResourceNotFoundException:
        """
        raise NotImplementedError

    @handler("ListRules")
    def list_rules(
        self,
        context: RequestContext,
        name_prefix: RuleName = None,
        event_bus_name: EventBusNameOrArn = None,
        next_token: NextToken = None,
        limit: LimitMax100 = None,
        **kwargs,
    ) -> ListRulesResponse:
        """Lists your Amazon EventBridge rules. You can either list all the rules
        or you can provide a prefix to match to the rule names.

        The maximum number of results per page for requests is 100.

        ListRules does not list the targets of a rule. To see the targets
        associated with a rule, use
        `ListTargetsByRule <https://docs.aws.amazon.com/eventbridge/latest/APIReference/API_ListTargetsByRule.html>`__.

        :param name_prefix: The prefix matching the rule name.
        :param event_bus_name: The name or ARN of the event bus to list the rules for.
        :param next_token: The token returned by a previous call to retrieve the next set of
        results.
        :param limit: The maximum number of results to return.
        :returns: ListRulesResponse
        :raises InternalException:
        :raises ResourceNotFoundException:
        """
        raise NotImplementedError

    @handler("ListTagsForResource")
    def list_tags_for_resource(
        self, context: RequestContext, resource_arn: Arn, **kwargs
    ) -> ListTagsForResourceResponse:
        """Displays the tags associated with an EventBridge resource. In
        EventBridge, rules and event buses can be tagged.

        :param resource_arn: The ARN of the EventBridge resource for which you want to view tags.
        :returns: ListTagsForResourceResponse
        :raises ResourceNotFoundException:
        :raises InternalException:
        """
        raise NotImplementedError

    @handler("ListTargetsByRule")
    def list_targets_by_rule(
        self,
        context: RequestContext,
        rule: RuleName,
        event_bus_name: EventBusNameOrArn = None,
        next_token: NextToken = None,
        limit: LimitMax100 = None,
        **kwargs,
    ) -> ListTargetsByRuleResponse:
        """Lists the targets assigned to the specified rule.

        The maximum number of results per page for requests is 100.

        :param rule: The name of the rule.
        :param event_bus_name: The name or ARN of the event bus associated with the rule.
        :param next_token: The token returned by a previous call to retrieve the next set of
        results.
        :param limit: The maximum number of results to return.
        :returns: ListTargetsByRuleResponse
        :raises ResourceNotFoundException:
        :raises InternalException:
        """
        raise NotImplementedError

    @handler("PutEvents")
    def put_events(
        self,
        context: RequestContext,
        entries: PutEventsRequestEntryList,
        endpoint_id: EndpointId = None,
        **kwargs,
    ) -> PutEventsResponse:
        """Sends custom events to Amazon EventBridge so that they can be matched to
        rules.

        The maximum size for a PutEvents event entry is 256 KB. Entry size is
        calculated including the event and any necessary characters and keys of
        the JSON representation of the event. To learn more, see `Calculating
        PutEvents event entry
        size <https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-putevent-size.html>`__
        in the *Amazon EventBridge User Guide*

        PutEvents accepts the data in JSON format. For the JSON number (integer)
        data type, the constraints are: a minimum value of
        -9,223,372,036,854,775,808 and a maximum value of
        9,223,372,036,854,775,807.

        PutEvents will only process nested JSON up to 1100 levels deep.

        :param entries: The entry that defines an event in your system.
        :param endpoint_id: The URL subdomain of the endpoint.
        :returns: PutEventsResponse
        :raises InternalException:
        """
        raise NotImplementedError

    @handler("PutPartnerEvents")
    def put_partner_events(
        self,
        context: RequestContext,
        entries: PutPartnerEventsRequestEntryList,
        **kwargs,
    ) -> PutPartnerEventsResponse:
        """This is used by SaaS partners to write events to a customer's partner
        event bus. Amazon Web Services customers do not use this operation.

        For information on calculating event batch size, see `Calculating
        EventBridge PutEvents event entry
        size <https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-putevent-size.html>`__
        in the *EventBridge User Guide*.

        :param entries: The list of events to write to the event bus.
        :returns: PutPartnerEventsResponse
        :raises InternalException:
        :raises OperationDisabledException:
        """
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
        **kwargs,
    ) -> None:
        """Running ``PutPermission`` permits the specified Amazon Web Services
        account or Amazon Web Services organization to put events to the
        specified *event bus*. Amazon EventBridge (CloudWatch Events) rules in
        your account are triggered by these events arriving to an event bus in
        your account.

        For another account to send events to your account, that external
        account must have an EventBridge rule with your account's event bus as a
        target.

        To enable multiple Amazon Web Services accounts to put events to your
        event bus, run ``PutPermission`` once for each of these accounts. Or, if
        all the accounts are members of the same Amazon Web Services
        organization, you can run ``PutPermission`` once specifying
        ``Principal`` as "\\*" and specifying the Amazon Web Services
        organization ID in ``Condition``, to grant permissions to all accounts
        in that organization.

        If you grant permissions using an organization, then accounts in that
        organization must specify a ``RoleArn`` with proper permissions when
        they use ``PutTarget`` to add your account's event bus as a target. For
        more information, see `Sending and Receiving Events Between Amazon Web
        Services
        Accounts <https://docs.aws.amazon.com/eventbridge/latest/userguide/eventbridge-cross-account-event-delivery.html>`__
        in the *Amazon EventBridge User Guide*.

        The permission policy on the event bus cannot exceed 10 KB in size.

        :param event_bus_name: The name of the event bus associated with the rule.
        :param action: The action that you are enabling the other account to perform.
        :param principal: The 12-digit Amazon Web Services account ID that you are permitting to
        put events to your default event bus.
        :param statement_id: An identifier string for the external account that you are granting
        permissions to.
        :param condition: This parameter enables you to limit the permission to accounts that
        fulfill a certain condition, such as being a member of a certain Amazon
        Web Services organization.
        :param policy: A JSON string that describes the permission policy statement.
        :raises ResourceNotFoundException:
        :raises PolicyLengthExceededException:
        :raises InternalException:
        :raises ConcurrentModificationException:
        :raises OperationDisabledException:
        """
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
        **kwargs,
    ) -> PutRuleResponse:
        """Creates or updates the specified rule. Rules are enabled by default, or
        based on value of the state. You can disable a rule using
        `DisableRule <https://docs.aws.amazon.com/eventbridge/latest/APIReference/API_DisableRule.html>`__.

        A single rule watches for events from a single event bus. Events
        generated by Amazon Web Services services go to your account's default
        event bus. Events generated by SaaS partner services or applications go
        to the matching partner event bus. If you have custom applications or
        services, you can specify whether their events go to your default event
        bus or a custom event bus that you have created. For more information,
        see
        `CreateEventBus <https://docs.aws.amazon.com/eventbridge/latest/APIReference/API_CreateEventBus.html>`__.

        If you are updating an existing rule, the rule is replaced with what you
        specify in this ``PutRule`` command. If you omit arguments in
        ``PutRule``, the old values for those arguments are not kept. Instead,
        they are replaced with null values.

        When you create or update a rule, incoming events might not immediately
        start matching to new or updated rules. Allow a short period of time for
        changes to take effect.

        A rule must contain at least an EventPattern or ScheduleExpression.
        Rules with EventPatterns are triggered when a matching event is
        observed. Rules with ScheduleExpressions self-trigger based on the given
        schedule. A rule can have both an EventPattern and a ScheduleExpression,
        in which case the rule triggers on matching events as well as on a
        schedule.

        When you initially create a rule, you can optionally assign one or more
        tags to the rule. Tags can help you organize and categorize your
        resources. You can also use them to scope user permissions, by granting
        a user permission to access or change only rules with certain tag
        values. To use the ``PutRule`` operation and assign tags, you must have
        both the ``events:PutRule`` and ``events:TagResource`` permissions.

        If you are updating an existing rule, any tags you specify in the
        ``PutRule`` operation are ignored. To update the tags of an existing
        rule, use
        `TagResource <https://docs.aws.amazon.com/eventbridge/latest/APIReference/API_TagResource.html>`__
        and
        `UntagResource <https://docs.aws.amazon.com/eventbridge/latest/APIReference/API_UntagResource.html>`__.

        Most services in Amazon Web Services treat : or / as the same character
        in Amazon Resource Names (ARNs). However, EventBridge uses an exact
        match in event patterns and rules. Be sure to use the correct ARN
        characters when creating event patterns so that they match the ARN
        syntax in the event you want to match.

        In EventBridge, it is possible to create rules that lead to infinite
        loops, where a rule is fired repeatedly. For example, a rule might
        detect that ACLs have changed on an S3 bucket, and trigger software to
        change them to the desired state. If the rule is not written carefully,
        the subsequent change to the ACLs fires the rule again, creating an
        infinite loop.

        To prevent this, write the rules so that the triggered actions do not
        re-fire the same rule. For example, your rule could fire only if ACLs
        are found to be in a bad state, instead of after any change.

        An infinite loop can quickly cause higher than expected charges. We
        recommend that you use budgeting, which alerts you when charges exceed
        your specified limit. For more information, see `Managing Your Costs
        with
        Budgets <https://docs.aws.amazon.com/awsaccountbilling/latest/aboutv2/budgets-managing-costs.html>`__.

        :param name: The name of the rule that you are creating or updating.
        :param schedule_expression: The scheduling expression.
        :param event_pattern: The event pattern.
        :param state: Indicates whether the rule is enabled or disabled.
        :param description: A description of the rule.
        :param role_arn: The Amazon Resource Name (ARN) of the IAM role associated with the rule.
        :param tags: The list of key-value pairs to associate with the rule.
        :param event_bus_name: The name or ARN of the event bus to associate with this rule.
        :returns: PutRuleResponse
        :raises InvalidEventPatternException:
        :raises LimitExceededException:
        :raises ConcurrentModificationException:
        :raises ManagedRuleException:
        :raises InternalException:
        :raises ResourceNotFoundException:
        """
        raise NotImplementedError

    @handler("PutTargets")
    def put_targets(
        self,
        context: RequestContext,
        rule: RuleName,
        targets: TargetList,
        event_bus_name: EventBusNameOrArn = None,
        **kwargs,
    ) -> PutTargetsResponse:
        """Adds the specified targets to the specified rule, or updates the targets
        if they are already associated with the rule.

        Targets are the resources that are invoked when a rule is triggered.

        The maximum number of entries per request is 10.

        Each rule can have up to five (5) targets associated with it at one
        time.

        For a list of services you can configure as targets for events, see
        `EventBridge
        targets <https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-targets.html>`__
        in the *Amazon EventBridge User Guide*.

        Creating rules with built-in targets is supported only in the Amazon Web
        Services Management Console. The built-in targets are:

        -  ``Amazon EBS CreateSnapshot API call``

        -  ``Amazon EC2 RebootInstances API call``

        -  ``Amazon EC2 StopInstances API call``

        -  ``Amazon EC2 TerminateInstances API call``

        For some target types, ``PutTargets`` provides target-specific
        parameters. If the target is a Kinesis data stream, you can optionally
        specify which shard the event goes to by using the ``KinesisParameters``
        argument. To invoke a command on multiple EC2 instances with one rule,
        you can use the ``RunCommandParameters`` field.

        To be able to make API calls against the resources that you own, Amazon
        EventBridge needs the appropriate permissions:

        -  For Lambda and Amazon SNS resources, EventBridge relies on
           resource-based policies.

        -  For EC2 instances, Kinesis Data Streams, Step Functions state
           machines and API Gateway APIs, EventBridge relies on IAM roles that
           you specify in the ``RoleARN`` argument in ``PutTargets``.

        For more information, see `Authentication and Access
        Control <https://docs.aws.amazon.com/eventbridge/latest/userguide/auth-and-access-control-eventbridge.html>`__
        in the *Amazon EventBridge User Guide*.

        If another Amazon Web Services account is in the same region and has
        granted you permission (using ``PutPermission``), you can send events to
        that account. Set that account's event bus as a target of the rules in
        your account. To send the matched events to the other account, specify
        that account's event bus as the ``Arn`` value when you run
        ``PutTargets``. If your account sends events to another account, your
        account is charged for each sent event. Each event sent to another
        account is charged as a custom event. The account receiving the event is
        not charged. For more information, see `Amazon EventBridge
        Pricing <http://aws.amazon.com/eventbridge/pricing/>`__.

        ``Input``, ``InputPath``, and ``InputTransformer`` are not available
        with ``PutTarget`` if the target is an event bus of a different Amazon
        Web Services account.

        If you are setting the event bus of another account as the target, and
        that account granted permission to your account through an organization
        instead of directly by the account ID, then you must specify a
        ``RoleArn`` with proper permissions in the ``Target`` structure. For
        more information, see `Sending and Receiving Events Between Amazon Web
        Services
        Accounts <https://docs.aws.amazon.com/eventbridge/latest/userguide/eventbridge-cross-account-event-delivery.html>`__
        in the *Amazon EventBridge User Guide*.

        If you have an IAM role on a cross-account event bus target, a
        ``PutTargets`` call without a role on the same target (same ``Id`` and
        ``Arn``) will not remove the role.

        For more information about enabling cross-account events, see
        `PutPermission <https://docs.aws.amazon.com/eventbridge/latest/APIReference/API_PutPermission.html>`__.

        **Input**, **InputPath**, and **InputTransformer** are mutually
        exclusive and optional parameters of a target. When a rule is triggered
        due to a matched event:

        -  If none of the following arguments are specified for a target, then
           the entire event is passed to the target in JSON format (unless the
           target is Amazon EC2 Run Command or Amazon ECS task, in which case
           nothing from the event is passed to the target).

        -  If **Input** is specified in the form of valid JSON, then the matched
           event is overridden with this constant.

        -  If **InputPath** is specified in the form of JSONPath (for example,
           ``$.detail``), then only the part of the event specified in the path
           is passed to the target (for example, only the detail part of the
           event is passed).

        -  If **InputTransformer** is specified, then one or more specified
           JSONPaths are extracted from the event and used as values in a
           template that you specify as the input to the target.

        When you specify ``InputPath`` or ``InputTransformer``, you must use
        JSON dot notation, not bracket notation.

        When you add targets to a rule and the associated rule triggers soon
        after, new or updated targets might not be immediately invoked. Allow a
        short period of time for changes to take effect.

        This action can partially fail if too many requests are made at the same
        time. If that happens, ``FailedEntryCount`` is non-zero in the response
        and each entry in ``FailedEntries`` provides the ID of the failed target
        and the error code.

        :param rule: The name of the rule.
        :param targets: The targets to update or add to the rule.
        :param event_bus_name: The name or ARN of the event bus associated with the rule.
        :returns: PutTargetsResponse
        :raises ResourceNotFoundException:
        :raises ConcurrentModificationException:
        :raises LimitExceededException:
        :raises ManagedRuleException:
        :raises InternalException:
        """
        raise NotImplementedError

    @handler("RemovePermission")
    def remove_permission(
        self,
        context: RequestContext,
        statement_id: StatementId = None,
        remove_all_permissions: Boolean = None,
        event_bus_name: NonPartnerEventBusName = None,
        **kwargs,
    ) -> None:
        """Revokes the permission of another Amazon Web Services account to be able
        to put events to the specified event bus. Specify the account to revoke
        by the ``StatementId`` value that you associated with the account when
        you granted it permission with ``PutPermission``. You can find the
        ``StatementId`` by using
        `DescribeEventBus <https://docs.aws.amazon.com/eventbridge/latest/APIReference/API_DescribeEventBus.html>`__.

        :param statement_id: The statement ID corresponding to the account that is no longer allowed
        to put events to the default event bus.
        :param remove_all_permissions: Specifies whether to remove all permissions.
        :param event_bus_name: The name of the event bus to revoke permissions for.
        :raises ResourceNotFoundException:
        :raises InternalException:
        :raises ConcurrentModificationException:
        :raises OperationDisabledException:
        """
        raise NotImplementedError

    @handler("RemoveTargets")
    def remove_targets(
        self,
        context: RequestContext,
        rule: RuleName,
        ids: TargetIdList,
        event_bus_name: EventBusNameOrArn = None,
        force: Boolean = None,
        **kwargs,
    ) -> RemoveTargetsResponse:
        """Removes the specified targets from the specified rule. When the rule is
        triggered, those targets are no longer be invoked.

        A successful execution of ``RemoveTargets`` doesn't guarantee all
        targets are removed from the rule, it means that the target(s) listed in
        the request are removed.

        When you remove a target, when the associated rule triggers, removed
        targets might continue to be invoked. Allow a short period of time for
        changes to take effect.

        This action can partially fail if too many requests are made at the same
        time. If that happens, ``FailedEntryCount`` is non-zero in the response
        and each entry in ``FailedEntries`` provides the ID of the failed target
        and the error code.

        The maximum number of entries per request is 10.

        :param rule: The name of the rule.
        :param ids: The IDs of the targets to remove from the rule.
        :param event_bus_name: The name or ARN of the event bus associated with the rule.
        :param force: If this is a managed rule, created by an Amazon Web Services service on
        your behalf, you must specify ``Force`` as ``True`` to remove targets.
        :returns: RemoveTargetsResponse
        :raises ResourceNotFoundException:
        :raises ConcurrentModificationException:
        :raises ManagedRuleException:
        :raises InternalException:
        """
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
        **kwargs,
    ) -> StartReplayResponse:
        """Starts the specified replay. Events are not necessarily replayed in the
        exact same order that they were added to the archive. A replay processes
        events to replay based on the time in the event, and replays them using
        1 minute intervals. If you specify an ``EventStartTime`` and an
        ``EventEndTime`` that covers a 20 minute time range, the events are
        replayed from the first minute of that 20 minute range first. Then the
        events from the second minute are replayed. You can use
        ``DescribeReplay`` to determine the progress of a replay. The value
        returned for ``EventLastReplayedTime`` indicates the time within the
        specified time range associated with the last event replayed.

        :param replay_name: The name of the replay to start.
        :param event_source_arn: The ARN of the archive to replay events from.
        :param event_start_time: A time stamp for the time to start replaying events.
        :param event_end_time: A time stamp for the time to stop replaying events.
        :param destination: A ``ReplayDestination`` object that includes details about the
        destination for the replay.
        :param description: A description for the replay to start.
        :returns: StartReplayResponse
        :raises ResourceNotFoundException:
        :raises ResourceAlreadyExistsException:
        :raises InvalidEventPatternException:
        :raises LimitExceededException:
        :raises InternalException:
        """
        raise NotImplementedError

    @handler("TagResource")
    def tag_resource(
        self, context: RequestContext, resource_arn: Arn, tags: TagList, **kwargs
    ) -> TagResourceResponse:
        """Assigns one or more tags (key-value pairs) to the specified EventBridge
        resource. Tags can help you organize and categorize your resources. You
        can also use them to scope user permissions by granting a user
        permission to access or change only resources with certain tag values.
        In EventBridge, rules and event buses can be tagged.

        Tags don't have any semantic meaning to Amazon Web Services and are
        interpreted strictly as strings of characters.

        You can use the ``TagResource`` action with a resource that already has
        tags. If you specify a new tag key, this tag is appended to the list of
        tags associated with the resource. If you specify a tag key that is
        already associated with the resource, the new tag value that you specify
        replaces the previous value for that tag.

        You can associate as many as 50 tags with a resource.

        :param resource_arn: The ARN of the EventBridge resource that you're adding tags to.
        :param tags: The list of key-value pairs to associate with the resource.
        :returns: TagResourceResponse
        :raises ResourceNotFoundException:
        :raises ConcurrentModificationException:
        :raises InternalException:
        :raises ManagedRuleException:
        """
        raise NotImplementedError

    @handler("TestEventPattern")
    def test_event_pattern(
        self,
        context: RequestContext,
        event_pattern: EventPattern,
        event: String,
        **kwargs,
    ) -> TestEventPatternResponse:
        """Tests whether the specified event pattern matches the provided event.

        Most services in Amazon Web Services treat : or / as the same character
        in Amazon Resource Names (ARNs). However, EventBridge uses an exact
        match in event patterns and rules. Be sure to use the correct ARN
        characters when creating event patterns so that they match the ARN
        syntax in the event you want to match.

        :param event_pattern: The event pattern.
        :param event: The event, in JSON format, to test against the event pattern.
        :returns: TestEventPatternResponse
        :raises InvalidEventPatternException:
        :raises InternalException:
        """
        raise NotImplementedError

    @handler("UntagResource")
    def untag_resource(
        self, context: RequestContext, resource_arn: Arn, tag_keys: TagKeyList, **kwargs
    ) -> UntagResourceResponse:
        """Removes one or more tags from the specified EventBridge resource. In
        Amazon EventBridge (CloudWatch Events), rules and event buses can be
        tagged.

        :param resource_arn: The ARN of the EventBridge resource from which you are removing tags.
        :param tag_keys: The list of tag keys to remove from the resource.
        :returns: UntagResourceResponse
        :raises ResourceNotFoundException:
        :raises InternalException:
        :raises ConcurrentModificationException:
        :raises ManagedRuleException:
        """
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
        **kwargs,
    ) -> UpdateApiDestinationResponse:
        """Updates an API destination.

        :param name: The name of the API destination to update.
        :param description: The name of the API destination to update.
        :param connection_arn: The ARN of the connection to use for the API destination.
        :param invocation_endpoint: The URL to the endpoint to use for the API destination.
        :param http_method: The method to use for the API destination.
        :param invocation_rate_limit_per_second: The maximum number of invocations per second to send to the API
        destination.
        :returns: UpdateApiDestinationResponse
        :raises ConcurrentModificationException:
        :raises ResourceNotFoundException:
        :raises InternalException:
        :raises LimitExceededException:
        """
        raise NotImplementedError

    @handler("UpdateArchive")
    def update_archive(
        self,
        context: RequestContext,
        archive_name: ArchiveName,
        description: ArchiveDescription = None,
        event_pattern: EventPattern = None,
        retention_days: RetentionDays = None,
        **kwargs,
    ) -> UpdateArchiveResponse:
        """Updates the specified archive.

        :param archive_name: The name of the archive to update.
        :param description: The description for the archive.
        :param event_pattern: The event pattern to use to filter events sent to the archive.
        :param retention_days: The number of days to retain events in the archive.
        :returns: UpdateArchiveResponse
        :raises ConcurrentModificationException:
        :raises ResourceNotFoundException:
        :raises InternalException:
        :raises LimitExceededException:
        :raises InvalidEventPatternException:
        """
        raise NotImplementedError

    @handler("UpdateConnection")
    def update_connection(
        self,
        context: RequestContext,
        name: ConnectionName,
        description: ConnectionDescription = None,
        authorization_type: ConnectionAuthorizationType = None,
        auth_parameters: UpdateConnectionAuthRequestParameters = None,
        **kwargs,
    ) -> UpdateConnectionResponse:
        """Updates settings for a connection.

        :param name: The name of the connection to update.
        :param description: A description for the connection.
        :param authorization_type: The type of authorization to use for the connection.
        :param auth_parameters: The authorization parameters to use for the connection.
        :returns: UpdateConnectionResponse
        :raises ConcurrentModificationException:
        :raises ResourceNotFoundException:
        :raises InternalException:
        :raises LimitExceededException:
        """
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
        **kwargs,
    ) -> UpdateEndpointResponse:
        """Update an existing endpoint. For more information about global
        endpoints, see `Making applications Regional-fault tolerant with global
        endpoints and event
        replication <https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-global-endpoints.html>`__
        in the *Amazon EventBridge User Guide*.

        :param name: The name of the endpoint you want to update.
        :param description: A description for the endpoint.
        :param routing_config: Configure the routing policy, including the health check and secondary
        Region.
        :param replication_config: Whether event replication was enabled or disabled by this request.
        :param event_buses: Define event buses used for replication.
        :param role_arn: The ARN of the role used by event replication for this request.
        :returns: UpdateEndpointResponse
        :raises ResourceNotFoundException:
        :raises ConcurrentModificationException:
        :raises InternalException:
        """
        raise NotImplementedError
