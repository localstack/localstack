from typing import Dict, List, Optional, TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

AccessPolicy = str
AccountId = str
AccountPolicyDocument = str
AmazonResourceName = str
Arn = str
ClientToken = str
DataProtectionPolicyDocument = str
Days = int
DefaultValue = float
Descending = bool
DescribeLimit = int
DescribeQueriesMaxResults = int
DestinationArn = str
DestinationName = str
DimensionsKey = str
DimensionsValue = str
EncryptionKey = str
EventId = str
EventMessage = str
EventsLimit = int
ExportDestinationBucket = str
ExportDestinationPrefix = str
ExportTaskId = str
ExportTaskName = str
ExportTaskStatusMessage = str
Field = str
FilterCount = int
FilterName = str
FilterPattern = str
ForceUpdate = bool
IncludeLinkedAccounts = bool
Interleaved = bool
KmsKeyId = str
LogEventIndex = int
LogGroupIdentifier = str
LogGroupName = str
LogGroupNamePattern = str
LogRecordPointer = str
LogStreamName = str
LogStreamSearchedCompletely = bool
Message = str
MetricName = str
MetricNamespace = str
MetricValue = str
NextToken = str
Percentage = int
PolicyDocument = str
PolicyName = str
QueryCharOffset = int
QueryDefinitionName = str
QueryDefinitionString = str
QueryId = str
QueryListMaxResults = int
QueryString = str
ResourceIdentifier = str
RoleArn = str
SequenceToken = str
StartFromHead = bool
StatsValue = float
Success = bool
TagKey = str
TagValue = str
TargetArn = str
Token = str
Unmask = bool
Value = str


class DataProtectionStatus(str):
    ACTIVATED = "ACTIVATED"
    DELETED = "DELETED"
    ARCHIVED = "ARCHIVED"
    DISABLED = "DISABLED"


class Distribution(str):
    Random = "Random"
    ByLogStream = "ByLogStream"


class ExportTaskStatusCode(str):
    CANCELLED = "CANCELLED"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    PENDING = "PENDING"
    PENDING_CANCEL = "PENDING_CANCEL"
    RUNNING = "RUNNING"


class InheritedProperty(str):
    ACCOUNT_DATA_PROTECTION = "ACCOUNT_DATA_PROTECTION"


class OrderBy(str):
    LogStreamName = "LogStreamName"
    LastEventTime = "LastEventTime"


class PolicyType(str):
    DATA_PROTECTION_POLICY = "DATA_PROTECTION_POLICY"


class QueryStatus(str):
    Scheduled = "Scheduled"
    Running = "Running"
    Complete = "Complete"
    Failed = "Failed"
    Cancelled = "Cancelled"
    Timeout = "Timeout"
    Unknown = "Unknown"


class Scope(str):
    ALL = "ALL"


class StandardUnit(str):
    Seconds = "Seconds"
    Microseconds = "Microseconds"
    Milliseconds = "Milliseconds"
    Bytes = "Bytes"
    Kilobytes = "Kilobytes"
    Megabytes = "Megabytes"
    Gigabytes = "Gigabytes"
    Terabytes = "Terabytes"
    Bits = "Bits"
    Kilobits = "Kilobits"
    Megabits = "Megabits"
    Gigabits = "Gigabits"
    Terabits = "Terabits"
    Percent = "Percent"
    Count = "Count"
    Bytes_Second = "Bytes/Second"
    Kilobytes_Second = "Kilobytes/Second"
    Megabytes_Second = "Megabytes/Second"
    Gigabytes_Second = "Gigabytes/Second"
    Terabytes_Second = "Terabytes/Second"
    Bits_Second = "Bits/Second"
    Kilobits_Second = "Kilobits/Second"
    Megabits_Second = "Megabits/Second"
    Gigabits_Second = "Gigabits/Second"
    Terabits_Second = "Terabits/Second"
    Count_Second = "Count/Second"
    None_ = "None"


class DataAlreadyAcceptedException(ServiceException):
    code: str = "DataAlreadyAcceptedException"
    sender_fault: bool = False
    status_code: int = 400
    expectedSequenceToken: Optional[SequenceToken]


class InvalidOperationException(ServiceException):
    code: str = "InvalidOperationException"
    sender_fault: bool = False
    status_code: int = 400


class InvalidParameterException(ServiceException):
    code: str = "InvalidParameterException"
    sender_fault: bool = False
    status_code: int = 400


class InvalidSequenceTokenException(ServiceException):
    code: str = "InvalidSequenceTokenException"
    sender_fault: bool = False
    status_code: int = 400
    expectedSequenceToken: Optional[SequenceToken]


class LimitExceededException(ServiceException):
    code: str = "LimitExceededException"
    sender_fault: bool = False
    status_code: int = 400


class QueryCompileErrorLocation(TypedDict, total=False):
    startCharOffset: Optional[QueryCharOffset]
    endCharOffset: Optional[QueryCharOffset]


class QueryCompileError(TypedDict, total=False):
    location: Optional[QueryCompileErrorLocation]
    message: Optional[Message]


class MalformedQueryException(ServiceException):
    code: str = "MalformedQueryException"
    sender_fault: bool = False
    status_code: int = 400
    queryCompileError: Optional[QueryCompileError]


class OperationAbortedException(ServiceException):
    code: str = "OperationAbortedException"
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


class ServiceUnavailableException(ServiceException):
    code: str = "ServiceUnavailableException"
    sender_fault: bool = False
    status_code: int = 400


class TooManyTagsException(ServiceException):
    code: str = "TooManyTagsException"
    sender_fault: bool = False
    status_code: int = 400
    resourceName: Optional[AmazonResourceName]


class UnrecognizedClientException(ServiceException):
    code: str = "UnrecognizedClientException"
    sender_fault: bool = False
    status_code: int = 400


AccountIds = List[AccountId]
Timestamp = int


class AccountPolicy(TypedDict, total=False):
    policyName: Optional[PolicyName]
    policyDocument: Optional[AccountPolicyDocument]
    lastUpdatedTime: Optional[Timestamp]
    policyType: Optional[PolicyType]
    scope: Optional[Scope]
    accountId: Optional[AccountId]


AccountPolicies = List[AccountPolicy]


class AssociateKmsKeyRequest(ServiceRequest):
    logGroupName: Optional[LogGroupName]
    kmsKeyId: KmsKeyId
    resourceIdentifier: Optional[ResourceIdentifier]


class CancelExportTaskRequest(ServiceRequest):
    taskId: ExportTaskId


CreateExportTaskRequest = TypedDict(
    "CreateExportTaskRequest",
    {
        "taskName": Optional[ExportTaskName],
        "logGroupName": LogGroupName,
        "logStreamNamePrefix": Optional[LogStreamName],
        "from": Timestamp,
        "to": Timestamp,
        "destination": ExportDestinationBucket,
        "destinationPrefix": Optional[ExportDestinationPrefix],
    },
    total=False,
)


class CreateExportTaskResponse(TypedDict, total=False):
    taskId: Optional[ExportTaskId]


Tags = Dict[TagKey, TagValue]


class CreateLogGroupRequest(ServiceRequest):
    logGroupName: LogGroupName
    kmsKeyId: Optional[KmsKeyId]
    tags: Optional[Tags]


class CreateLogStreamRequest(ServiceRequest):
    logGroupName: LogGroupName
    logStreamName: LogStreamName


class DeleteAccountPolicyRequest(ServiceRequest):
    policyName: PolicyName
    policyType: PolicyType


class DeleteDataProtectionPolicyRequest(ServiceRequest):
    logGroupIdentifier: LogGroupIdentifier


class DeleteDestinationRequest(ServiceRequest):
    destinationName: DestinationName


class DeleteLogGroupRequest(ServiceRequest):
    logGroupName: LogGroupName


class DeleteLogStreamRequest(ServiceRequest):
    logGroupName: LogGroupName
    logStreamName: LogStreamName


class DeleteMetricFilterRequest(ServiceRequest):
    logGroupName: LogGroupName
    filterName: FilterName


class DeleteQueryDefinitionRequest(ServiceRequest):
    queryDefinitionId: QueryId


class DeleteQueryDefinitionResponse(TypedDict, total=False):
    success: Optional[Success]


class DeleteResourcePolicyRequest(ServiceRequest):
    policyName: Optional[PolicyName]


class DeleteRetentionPolicyRequest(ServiceRequest):
    logGroupName: LogGroupName


class DeleteSubscriptionFilterRequest(ServiceRequest):
    logGroupName: LogGroupName
    filterName: FilterName


class DescribeAccountPoliciesRequest(ServiceRequest):
    policyType: PolicyType
    policyName: Optional[PolicyName]
    accountIdentifiers: Optional[AccountIds]


class DescribeAccountPoliciesResponse(TypedDict, total=False):
    accountPolicies: Optional[AccountPolicies]


class DescribeDestinationsRequest(ServiceRequest):
    DestinationNamePrefix: Optional[DestinationName]
    nextToken: Optional[NextToken]
    limit: Optional[DescribeLimit]


class Destination(TypedDict, total=False):
    destinationName: Optional[DestinationName]
    targetArn: Optional[TargetArn]
    roleArn: Optional[RoleArn]
    accessPolicy: Optional[AccessPolicy]
    arn: Optional[Arn]
    creationTime: Optional[Timestamp]


Destinations = List[Destination]


class DescribeDestinationsResponse(TypedDict, total=False):
    destinations: Optional[Destinations]
    nextToken: Optional[NextToken]


class DescribeExportTasksRequest(ServiceRequest):
    taskId: Optional[ExportTaskId]
    statusCode: Optional[ExportTaskStatusCode]
    nextToken: Optional[NextToken]
    limit: Optional[DescribeLimit]


class ExportTaskExecutionInfo(TypedDict, total=False):
    creationTime: Optional[Timestamp]
    completionTime: Optional[Timestamp]


class ExportTaskStatus(TypedDict, total=False):
    code: Optional[ExportTaskStatusCode]
    message: Optional[ExportTaskStatusMessage]


ExportTask = TypedDict(
    "ExportTask",
    {
        "taskId": Optional[ExportTaskId],
        "taskName": Optional[ExportTaskName],
        "logGroupName": Optional[LogGroupName],
        "from": Optional[Timestamp],
        "to": Optional[Timestamp],
        "destination": Optional[ExportDestinationBucket],
        "destinationPrefix": Optional[ExportDestinationPrefix],
        "status": Optional[ExportTaskStatus],
        "executionInfo": Optional[ExportTaskExecutionInfo],
    },
    total=False,
)
ExportTasks = List[ExportTask]


class DescribeExportTasksResponse(TypedDict, total=False):
    exportTasks: Optional[ExportTasks]
    nextToken: Optional[NextToken]


class DescribeLogGroupsRequest(ServiceRequest):
    accountIdentifiers: Optional[AccountIds]
    logGroupNamePrefix: Optional[LogGroupName]
    logGroupNamePattern: Optional[LogGroupNamePattern]
    nextToken: Optional[NextToken]
    limit: Optional[DescribeLimit]
    includeLinkedAccounts: Optional[IncludeLinkedAccounts]


InheritedProperties = List[InheritedProperty]
StoredBytes = int


class LogGroup(TypedDict, total=False):
    logGroupName: Optional[LogGroupName]
    creationTime: Optional[Timestamp]
    retentionInDays: Optional[Days]
    metricFilterCount: Optional[FilterCount]
    arn: Optional[Arn]
    storedBytes: Optional[StoredBytes]
    kmsKeyId: Optional[KmsKeyId]
    dataProtectionStatus: Optional[DataProtectionStatus]
    inheritedProperties: Optional[InheritedProperties]


LogGroups = List[LogGroup]


class DescribeLogGroupsResponse(TypedDict, total=False):
    logGroups: Optional[LogGroups]
    nextToken: Optional[NextToken]


class DescribeLogStreamsRequest(ServiceRequest):
    logGroupName: Optional[LogGroupName]
    logGroupIdentifier: Optional[LogGroupIdentifier]
    logStreamNamePrefix: Optional[LogStreamName]
    orderBy: Optional[OrderBy]
    descending: Optional[Descending]
    nextToken: Optional[NextToken]
    limit: Optional[DescribeLimit]


class LogStream(TypedDict, total=False):
    logStreamName: Optional[LogStreamName]
    creationTime: Optional[Timestamp]
    firstEventTimestamp: Optional[Timestamp]
    lastEventTimestamp: Optional[Timestamp]
    lastIngestionTime: Optional[Timestamp]
    uploadSequenceToken: Optional[SequenceToken]
    arn: Optional[Arn]
    storedBytes: Optional[StoredBytes]


LogStreams = List[LogStream]


class DescribeLogStreamsResponse(TypedDict, total=False):
    logStreams: Optional[LogStreams]
    nextToken: Optional[NextToken]


class DescribeMetricFiltersRequest(ServiceRequest):
    logGroupName: Optional[LogGroupName]
    filterNamePrefix: Optional[FilterName]
    nextToken: Optional[NextToken]
    limit: Optional[DescribeLimit]
    metricName: Optional[MetricName]
    metricNamespace: Optional[MetricNamespace]


Dimensions = Dict[DimensionsKey, DimensionsValue]


class MetricTransformation(TypedDict, total=False):
    metricName: MetricName
    metricNamespace: MetricNamespace
    metricValue: MetricValue
    defaultValue: Optional[DefaultValue]
    dimensions: Optional[Dimensions]
    unit: Optional[StandardUnit]


MetricTransformations = List[MetricTransformation]


class MetricFilter(TypedDict, total=False):
    filterName: Optional[FilterName]
    filterPattern: Optional[FilterPattern]
    metricTransformations: Optional[MetricTransformations]
    creationTime: Optional[Timestamp]
    logGroupName: Optional[LogGroupName]


MetricFilters = List[MetricFilter]


class DescribeMetricFiltersResponse(TypedDict, total=False):
    metricFilters: Optional[MetricFilters]
    nextToken: Optional[NextToken]


class DescribeQueriesRequest(ServiceRequest):
    logGroupName: Optional[LogGroupName]
    status: Optional[QueryStatus]
    maxResults: Optional[DescribeQueriesMaxResults]
    nextToken: Optional[NextToken]


class QueryInfo(TypedDict, total=False):
    queryId: Optional[QueryId]
    queryString: Optional[QueryString]
    status: Optional[QueryStatus]
    createTime: Optional[Timestamp]
    logGroupName: Optional[LogGroupName]


QueryInfoList = List[QueryInfo]


class DescribeQueriesResponse(TypedDict, total=False):
    queries: Optional[QueryInfoList]
    nextToken: Optional[NextToken]


class DescribeQueryDefinitionsRequest(ServiceRequest):
    queryDefinitionNamePrefix: Optional[QueryDefinitionName]
    maxResults: Optional[QueryListMaxResults]
    nextToken: Optional[NextToken]


LogGroupNames = List[LogGroupName]


class QueryDefinition(TypedDict, total=False):
    queryDefinitionId: Optional[QueryId]
    name: Optional[QueryDefinitionName]
    queryString: Optional[QueryDefinitionString]
    lastModified: Optional[Timestamp]
    logGroupNames: Optional[LogGroupNames]


QueryDefinitionList = List[QueryDefinition]


class DescribeQueryDefinitionsResponse(TypedDict, total=False):
    queryDefinitions: Optional[QueryDefinitionList]
    nextToken: Optional[NextToken]


class DescribeResourcePoliciesRequest(ServiceRequest):
    nextToken: Optional[NextToken]
    limit: Optional[DescribeLimit]


class ResourcePolicy(TypedDict, total=False):
    policyName: Optional[PolicyName]
    policyDocument: Optional[PolicyDocument]
    lastUpdatedTime: Optional[Timestamp]


ResourcePolicies = List[ResourcePolicy]


class DescribeResourcePoliciesResponse(TypedDict, total=False):
    resourcePolicies: Optional[ResourcePolicies]
    nextToken: Optional[NextToken]


class DescribeSubscriptionFiltersRequest(ServiceRequest):
    logGroupName: LogGroupName
    filterNamePrefix: Optional[FilterName]
    nextToken: Optional[NextToken]
    limit: Optional[DescribeLimit]


class SubscriptionFilter(TypedDict, total=False):
    filterName: Optional[FilterName]
    logGroupName: Optional[LogGroupName]
    filterPattern: Optional[FilterPattern]
    destinationArn: Optional[DestinationArn]
    roleArn: Optional[RoleArn]
    distribution: Optional[Distribution]
    creationTime: Optional[Timestamp]


SubscriptionFilters = List[SubscriptionFilter]


class DescribeSubscriptionFiltersResponse(TypedDict, total=False):
    subscriptionFilters: Optional[SubscriptionFilters]
    nextToken: Optional[NextToken]


class DisassociateKmsKeyRequest(ServiceRequest):
    logGroupName: Optional[LogGroupName]
    resourceIdentifier: Optional[ResourceIdentifier]


EventNumber = int
ExtractedValues = Dict[Token, Value]
InputLogStreamNames = List[LogStreamName]


class FilterLogEventsRequest(ServiceRequest):
    logGroupName: Optional[LogGroupName]
    logGroupIdentifier: Optional[LogGroupIdentifier]
    logStreamNames: Optional[InputLogStreamNames]
    logStreamNamePrefix: Optional[LogStreamName]
    startTime: Optional[Timestamp]
    endTime: Optional[Timestamp]
    filterPattern: Optional[FilterPattern]
    nextToken: Optional[NextToken]
    limit: Optional[EventsLimit]
    interleaved: Optional[Interleaved]
    unmask: Optional[Unmask]


class SearchedLogStream(TypedDict, total=False):
    logStreamName: Optional[LogStreamName]
    searchedCompletely: Optional[LogStreamSearchedCompletely]


SearchedLogStreams = List[SearchedLogStream]


class FilteredLogEvent(TypedDict, total=False):
    logStreamName: Optional[LogStreamName]
    timestamp: Optional[Timestamp]
    message: Optional[EventMessage]
    ingestionTime: Optional[Timestamp]
    eventId: Optional[EventId]


FilteredLogEvents = List[FilteredLogEvent]


class FilterLogEventsResponse(TypedDict, total=False):
    events: Optional[FilteredLogEvents]
    searchedLogStreams: Optional[SearchedLogStreams]
    nextToken: Optional[NextToken]


class GetDataProtectionPolicyRequest(ServiceRequest):
    logGroupIdentifier: LogGroupIdentifier


class GetDataProtectionPolicyResponse(TypedDict, total=False):
    logGroupIdentifier: Optional[LogGroupIdentifier]
    policyDocument: Optional[DataProtectionPolicyDocument]
    lastUpdatedTime: Optional[Timestamp]


class GetLogEventsRequest(ServiceRequest):
    logGroupName: Optional[LogGroupName]
    logGroupIdentifier: Optional[LogGroupIdentifier]
    logStreamName: LogStreamName
    startTime: Optional[Timestamp]
    endTime: Optional[Timestamp]
    nextToken: Optional[NextToken]
    limit: Optional[EventsLimit]
    startFromHead: Optional[StartFromHead]
    unmask: Optional[Unmask]


class OutputLogEvent(TypedDict, total=False):
    timestamp: Optional[Timestamp]
    message: Optional[EventMessage]
    ingestionTime: Optional[Timestamp]


OutputLogEvents = List[OutputLogEvent]


class GetLogEventsResponse(TypedDict, total=False):
    events: Optional[OutputLogEvents]
    nextForwardToken: Optional[NextToken]
    nextBackwardToken: Optional[NextToken]


class GetLogGroupFieldsRequest(ServiceRequest):
    logGroupName: Optional[LogGroupName]
    time: Optional[Timestamp]
    logGroupIdentifier: Optional[LogGroupIdentifier]


class LogGroupField(TypedDict, total=False):
    name: Optional[Field]
    percent: Optional[Percentage]


LogGroupFieldList = List[LogGroupField]


class GetLogGroupFieldsResponse(TypedDict, total=False):
    logGroupFields: Optional[LogGroupFieldList]


class GetLogRecordRequest(ServiceRequest):
    logRecordPointer: LogRecordPointer
    unmask: Optional[Unmask]


LogRecord = Dict[Field, Value]


class GetLogRecordResponse(TypedDict, total=False):
    logRecord: Optional[LogRecord]


class GetQueryResultsRequest(ServiceRequest):
    queryId: QueryId


class QueryStatistics(TypedDict, total=False):
    recordsMatched: Optional[StatsValue]
    recordsScanned: Optional[StatsValue]
    bytesScanned: Optional[StatsValue]


class ResultField(TypedDict, total=False):
    field: Optional[Field]
    value: Optional[Value]


ResultRows = List[ResultField]
QueryResults = List[ResultRows]


class GetQueryResultsResponse(TypedDict, total=False):
    results: Optional[QueryResults]
    statistics: Optional[QueryStatistics]
    status: Optional[QueryStatus]
    encryptionKey: Optional[EncryptionKey]


class InputLogEvent(TypedDict, total=False):
    timestamp: Timestamp
    message: EventMessage


InputLogEvents = List[InputLogEvent]


class ListTagsForResourceRequest(ServiceRequest):
    resourceArn: AmazonResourceName


class ListTagsForResourceResponse(TypedDict, total=False):
    tags: Optional[Tags]


class ListTagsLogGroupRequest(ServiceRequest):
    logGroupName: LogGroupName


class ListTagsLogGroupResponse(TypedDict, total=False):
    tags: Optional[Tags]


LogGroupIdentifiers = List[LogGroupIdentifier]


class MetricFilterMatchRecord(TypedDict, total=False):
    eventNumber: Optional[EventNumber]
    eventMessage: Optional[EventMessage]
    extractedValues: Optional[ExtractedValues]


MetricFilterMatches = List[MetricFilterMatchRecord]


class PutAccountPolicyRequest(ServiceRequest):
    policyName: PolicyName
    policyDocument: AccountPolicyDocument
    policyType: PolicyType
    scope: Optional[Scope]


class PutAccountPolicyResponse(TypedDict, total=False):
    accountPolicy: Optional[AccountPolicy]


class PutDataProtectionPolicyRequest(ServiceRequest):
    logGroupIdentifier: LogGroupIdentifier
    policyDocument: DataProtectionPolicyDocument


class PutDataProtectionPolicyResponse(TypedDict, total=False):
    logGroupIdentifier: Optional[LogGroupIdentifier]
    policyDocument: Optional[DataProtectionPolicyDocument]
    lastUpdatedTime: Optional[Timestamp]


class PutDestinationPolicyRequest(ServiceRequest):
    destinationName: DestinationName
    accessPolicy: AccessPolicy
    forceUpdate: Optional[ForceUpdate]


class PutDestinationRequest(ServiceRequest):
    destinationName: DestinationName
    targetArn: TargetArn
    roleArn: RoleArn
    tags: Optional[Tags]


class PutDestinationResponse(TypedDict, total=False):
    destination: Optional[Destination]


class PutLogEventsRequest(ServiceRequest):
    logGroupName: LogGroupName
    logStreamName: LogStreamName
    logEvents: InputLogEvents
    sequenceToken: Optional[SequenceToken]


class RejectedLogEventsInfo(TypedDict, total=False):
    tooNewLogEventStartIndex: Optional[LogEventIndex]
    tooOldLogEventEndIndex: Optional[LogEventIndex]
    expiredLogEventEndIndex: Optional[LogEventIndex]


class PutLogEventsResponse(TypedDict, total=False):
    nextSequenceToken: Optional[SequenceToken]
    rejectedLogEventsInfo: Optional[RejectedLogEventsInfo]


class PutMetricFilterRequest(ServiceRequest):
    logGroupName: LogGroupName
    filterName: FilterName
    filterPattern: FilterPattern
    metricTransformations: MetricTransformations


class PutQueryDefinitionRequest(ServiceRequest):
    name: QueryDefinitionName
    queryDefinitionId: Optional[QueryId]
    logGroupNames: Optional[LogGroupNames]
    queryString: QueryDefinitionString
    clientToken: Optional[ClientToken]


class PutQueryDefinitionResponse(TypedDict, total=False):
    queryDefinitionId: Optional[QueryId]


class PutResourcePolicyRequest(ServiceRequest):
    policyName: Optional[PolicyName]
    policyDocument: Optional[PolicyDocument]


class PutResourcePolicyResponse(TypedDict, total=False):
    resourcePolicy: Optional[ResourcePolicy]


class PutRetentionPolicyRequest(ServiceRequest):
    logGroupName: LogGroupName
    retentionInDays: Days


class PutSubscriptionFilterRequest(ServiceRequest):
    logGroupName: LogGroupName
    filterName: FilterName
    filterPattern: FilterPattern
    destinationArn: DestinationArn
    roleArn: Optional[RoleArn]
    distribution: Optional[Distribution]


class StartQueryRequest(ServiceRequest):
    logGroupName: Optional[LogGroupName]
    logGroupNames: Optional[LogGroupNames]
    logGroupIdentifiers: Optional[LogGroupIdentifiers]
    startTime: Timestamp
    endTime: Timestamp
    queryString: QueryString
    limit: Optional[EventsLimit]


class StartQueryResponse(TypedDict, total=False):
    queryId: Optional[QueryId]


class StopQueryRequest(ServiceRequest):
    queryId: QueryId


class StopQueryResponse(TypedDict, total=False):
    success: Optional[Success]


TagKeyList = List[TagKey]
TagList = List[TagKey]


class TagLogGroupRequest(ServiceRequest):
    logGroupName: LogGroupName
    tags: Tags


class TagResourceRequest(ServiceRequest):
    resourceArn: AmazonResourceName
    tags: Tags


TestEventMessages = List[EventMessage]


class TestMetricFilterRequest(ServiceRequest):
    filterPattern: FilterPattern
    logEventMessages: TestEventMessages


class TestMetricFilterResponse(TypedDict, total=False):
    matches: Optional[MetricFilterMatches]


class UntagLogGroupRequest(ServiceRequest):
    logGroupName: LogGroupName
    tags: TagList


class UntagResourceRequest(ServiceRequest):
    resourceArn: AmazonResourceName
    tagKeys: TagKeyList


class LogsApi:
    service = "logs"
    version = "2014-03-28"

    @handler("AssociateKmsKey")
    def associate_kms_key(
        self,
        context: RequestContext,
        kms_key_id: KmsKeyId,
        log_group_name: LogGroupName = None,
        resource_identifier: ResourceIdentifier = None,
    ) -> None:
        raise NotImplementedError

    @handler("CancelExportTask")
    def cancel_export_task(self, context: RequestContext, task_id: ExportTaskId) -> None:
        raise NotImplementedError

    @handler("CreateExportTask", expand=False)
    def create_export_task(
        self, context: RequestContext, request: CreateExportTaskRequest
    ) -> CreateExportTaskResponse:
        raise NotImplementedError

    @handler("CreateLogGroup")
    def create_log_group(
        self,
        context: RequestContext,
        log_group_name: LogGroupName,
        kms_key_id: KmsKeyId = None,
        tags: Tags = None,
    ) -> None:
        raise NotImplementedError

    @handler("CreateLogStream")
    def create_log_stream(
        self, context: RequestContext, log_group_name: LogGroupName, log_stream_name: LogStreamName
    ) -> None:
        raise NotImplementedError

    @handler("DeleteAccountPolicy")
    def delete_account_policy(
        self, context: RequestContext, policy_name: PolicyName, policy_type: PolicyType
    ) -> None:
        raise NotImplementedError

    @handler("DeleteDataProtectionPolicy")
    def delete_data_protection_policy(
        self, context: RequestContext, log_group_identifier: LogGroupIdentifier
    ) -> None:
        raise NotImplementedError

    @handler("DeleteDestination")
    def delete_destination(
        self, context: RequestContext, destination_name: DestinationName
    ) -> None:
        raise NotImplementedError

    @handler("DeleteLogGroup")
    def delete_log_group(self, context: RequestContext, log_group_name: LogGroupName) -> None:
        raise NotImplementedError

    @handler("DeleteLogStream")
    def delete_log_stream(
        self, context: RequestContext, log_group_name: LogGroupName, log_stream_name: LogStreamName
    ) -> None:
        raise NotImplementedError

    @handler("DeleteMetricFilter")
    def delete_metric_filter(
        self, context: RequestContext, log_group_name: LogGroupName, filter_name: FilterName
    ) -> None:
        raise NotImplementedError

    @handler("DeleteQueryDefinition")
    def delete_query_definition(
        self, context: RequestContext, query_definition_id: QueryId
    ) -> DeleteQueryDefinitionResponse:
        raise NotImplementedError

    @handler("DeleteResourcePolicy")
    def delete_resource_policy(
        self, context: RequestContext, policy_name: PolicyName = None
    ) -> None:
        raise NotImplementedError

    @handler("DeleteRetentionPolicy")
    def delete_retention_policy(
        self, context: RequestContext, log_group_name: LogGroupName
    ) -> None:
        raise NotImplementedError

    @handler("DeleteSubscriptionFilter")
    def delete_subscription_filter(
        self, context: RequestContext, log_group_name: LogGroupName, filter_name: FilterName
    ) -> None:
        raise NotImplementedError

    @handler("DescribeAccountPolicies")
    def describe_account_policies(
        self,
        context: RequestContext,
        policy_type: PolicyType,
        policy_name: PolicyName = None,
        account_identifiers: AccountIds = None,
    ) -> DescribeAccountPoliciesResponse:
        raise NotImplementedError

    @handler("DescribeDestinations")
    def describe_destinations(
        self,
        context: RequestContext,
        destination_name_prefix: DestinationName = None,
        next_token: NextToken = None,
        limit: DescribeLimit = None,
    ) -> DescribeDestinationsResponse:
        raise NotImplementedError

    @handler("DescribeExportTasks")
    def describe_export_tasks(
        self,
        context: RequestContext,
        task_id: ExportTaskId = None,
        status_code: ExportTaskStatusCode = None,
        next_token: NextToken = None,
        limit: DescribeLimit = None,
    ) -> DescribeExportTasksResponse:
        raise NotImplementedError

    @handler("DescribeLogGroups")
    def describe_log_groups(
        self,
        context: RequestContext,
        account_identifiers: AccountIds = None,
        log_group_name_prefix: LogGroupName = None,
        log_group_name_pattern: LogGroupNamePattern = None,
        next_token: NextToken = None,
        limit: DescribeLimit = None,
        include_linked_accounts: IncludeLinkedAccounts = None,
    ) -> DescribeLogGroupsResponse:
        raise NotImplementedError

    @handler("DescribeLogStreams")
    def describe_log_streams(
        self,
        context: RequestContext,
        log_group_name: LogGroupName = None,
        log_group_identifier: LogGroupIdentifier = None,
        log_stream_name_prefix: LogStreamName = None,
        order_by: OrderBy = None,
        descending: Descending = None,
        next_token: NextToken = None,
        limit: DescribeLimit = None,
    ) -> DescribeLogStreamsResponse:
        raise NotImplementedError

    @handler("DescribeMetricFilters")
    def describe_metric_filters(
        self,
        context: RequestContext,
        log_group_name: LogGroupName = None,
        filter_name_prefix: FilterName = None,
        next_token: NextToken = None,
        limit: DescribeLimit = None,
        metric_name: MetricName = None,
        metric_namespace: MetricNamespace = None,
    ) -> DescribeMetricFiltersResponse:
        raise NotImplementedError

    @handler("DescribeQueries")
    def describe_queries(
        self,
        context: RequestContext,
        log_group_name: LogGroupName = None,
        status: QueryStatus = None,
        max_results: DescribeQueriesMaxResults = None,
        next_token: NextToken = None,
    ) -> DescribeQueriesResponse:
        raise NotImplementedError

    @handler("DescribeQueryDefinitions")
    def describe_query_definitions(
        self,
        context: RequestContext,
        query_definition_name_prefix: QueryDefinitionName = None,
        max_results: QueryListMaxResults = None,
        next_token: NextToken = None,
    ) -> DescribeQueryDefinitionsResponse:
        raise NotImplementedError

    @handler("DescribeResourcePolicies")
    def describe_resource_policies(
        self, context: RequestContext, next_token: NextToken = None, limit: DescribeLimit = None
    ) -> DescribeResourcePoliciesResponse:
        raise NotImplementedError

    @handler("DescribeSubscriptionFilters")
    def describe_subscription_filters(
        self,
        context: RequestContext,
        log_group_name: LogGroupName,
        filter_name_prefix: FilterName = None,
        next_token: NextToken = None,
        limit: DescribeLimit = None,
    ) -> DescribeSubscriptionFiltersResponse:
        raise NotImplementedError

    @handler("DisassociateKmsKey")
    def disassociate_kms_key(
        self,
        context: RequestContext,
        log_group_name: LogGroupName = None,
        resource_identifier: ResourceIdentifier = None,
    ) -> None:
        raise NotImplementedError

    @handler("FilterLogEvents")
    def filter_log_events(
        self,
        context: RequestContext,
        log_group_name: LogGroupName = None,
        log_group_identifier: LogGroupIdentifier = None,
        log_stream_names: InputLogStreamNames = None,
        log_stream_name_prefix: LogStreamName = None,
        start_time: Timestamp = None,
        end_time: Timestamp = None,
        filter_pattern: FilterPattern = None,
        next_token: NextToken = None,
        limit: EventsLimit = None,
        interleaved: Interleaved = None,
        unmask: Unmask = None,
    ) -> FilterLogEventsResponse:
        raise NotImplementedError

    @handler("GetDataProtectionPolicy")
    def get_data_protection_policy(
        self, context: RequestContext, log_group_identifier: LogGroupIdentifier
    ) -> GetDataProtectionPolicyResponse:
        raise NotImplementedError

    @handler("GetLogEvents")
    def get_log_events(
        self,
        context: RequestContext,
        log_stream_name: LogStreamName,
        log_group_name: LogGroupName = None,
        log_group_identifier: LogGroupIdentifier = None,
        start_time: Timestamp = None,
        end_time: Timestamp = None,
        next_token: NextToken = None,
        limit: EventsLimit = None,
        start_from_head: StartFromHead = None,
        unmask: Unmask = None,
    ) -> GetLogEventsResponse:
        raise NotImplementedError

    @handler("GetLogGroupFields")
    def get_log_group_fields(
        self,
        context: RequestContext,
        log_group_name: LogGroupName = None,
        time: Timestamp = None,
        log_group_identifier: LogGroupIdentifier = None,
    ) -> GetLogGroupFieldsResponse:
        raise NotImplementedError

    @handler("GetLogRecord")
    def get_log_record(
        self, context: RequestContext, log_record_pointer: LogRecordPointer, unmask: Unmask = None
    ) -> GetLogRecordResponse:
        raise NotImplementedError

    @handler("GetQueryResults")
    def get_query_results(
        self, context: RequestContext, query_id: QueryId
    ) -> GetQueryResultsResponse:
        raise NotImplementedError

    @handler("ListTagsForResource")
    def list_tags_for_resource(
        self, context: RequestContext, resource_arn: AmazonResourceName
    ) -> ListTagsForResourceResponse:
        raise NotImplementedError

    @handler("ListTagsLogGroup")
    def list_tags_log_group(
        self, context: RequestContext, log_group_name: LogGroupName
    ) -> ListTagsLogGroupResponse:
        raise NotImplementedError

    @handler("PutAccountPolicy")
    def put_account_policy(
        self,
        context: RequestContext,
        policy_name: PolicyName,
        policy_document: AccountPolicyDocument,
        policy_type: PolicyType,
        scope: Scope = None,
    ) -> PutAccountPolicyResponse:
        raise NotImplementedError

    @handler("PutDataProtectionPolicy")
    def put_data_protection_policy(
        self,
        context: RequestContext,
        log_group_identifier: LogGroupIdentifier,
        policy_document: DataProtectionPolicyDocument,
    ) -> PutDataProtectionPolicyResponse:
        raise NotImplementedError

    @handler("PutDestination")
    def put_destination(
        self,
        context: RequestContext,
        destination_name: DestinationName,
        target_arn: TargetArn,
        role_arn: RoleArn,
        tags: Tags = None,
    ) -> PutDestinationResponse:
        raise NotImplementedError

    @handler("PutDestinationPolicy")
    def put_destination_policy(
        self,
        context: RequestContext,
        destination_name: DestinationName,
        access_policy: AccessPolicy,
        force_update: ForceUpdate = None,
    ) -> None:
        raise NotImplementedError

    @handler("PutLogEvents")
    def put_log_events(
        self,
        context: RequestContext,
        log_group_name: LogGroupName,
        log_stream_name: LogStreamName,
        log_events: InputLogEvents,
        sequence_token: SequenceToken = None,
    ) -> PutLogEventsResponse:
        raise NotImplementedError

    @handler("PutMetricFilter")
    def put_metric_filter(
        self,
        context: RequestContext,
        log_group_name: LogGroupName,
        filter_name: FilterName,
        filter_pattern: FilterPattern,
        metric_transformations: MetricTransformations,
    ) -> None:
        raise NotImplementedError

    @handler("PutQueryDefinition")
    def put_query_definition(
        self,
        context: RequestContext,
        name: QueryDefinitionName,
        query_string: QueryDefinitionString,
        query_definition_id: QueryId = None,
        log_group_names: LogGroupNames = None,
        client_token: ClientToken = None,
    ) -> PutQueryDefinitionResponse:
        raise NotImplementedError

    @handler("PutResourcePolicy")
    def put_resource_policy(
        self,
        context: RequestContext,
        policy_name: PolicyName = None,
        policy_document: PolicyDocument = None,
    ) -> PutResourcePolicyResponse:
        raise NotImplementedError

    @handler("PutRetentionPolicy")
    def put_retention_policy(
        self, context: RequestContext, log_group_name: LogGroupName, retention_in_days: Days
    ) -> None:
        raise NotImplementedError

    @handler("PutSubscriptionFilter")
    def put_subscription_filter(
        self,
        context: RequestContext,
        log_group_name: LogGroupName,
        filter_name: FilterName,
        filter_pattern: FilterPattern,
        destination_arn: DestinationArn,
        role_arn: RoleArn = None,
        distribution: Distribution = None,
    ) -> None:
        raise NotImplementedError

    @handler("StartQuery")
    def start_query(
        self,
        context: RequestContext,
        start_time: Timestamp,
        end_time: Timestamp,
        query_string: QueryString,
        log_group_name: LogGroupName = None,
        log_group_names: LogGroupNames = None,
        log_group_identifiers: LogGroupIdentifiers = None,
        limit: EventsLimit = None,
    ) -> StartQueryResponse:
        raise NotImplementedError

    @handler("StopQuery")
    def stop_query(self, context: RequestContext, query_id: QueryId) -> StopQueryResponse:
        raise NotImplementedError

    @handler("TagLogGroup")
    def tag_log_group(
        self, context: RequestContext, log_group_name: LogGroupName, tags: Tags
    ) -> None:
        raise NotImplementedError

    @handler("TagResource")
    def tag_resource(
        self, context: RequestContext, resource_arn: AmazonResourceName, tags: Tags
    ) -> None:
        raise NotImplementedError

    @handler("TestMetricFilter")
    def test_metric_filter(
        self,
        context: RequestContext,
        filter_pattern: FilterPattern,
        log_event_messages: TestEventMessages,
    ) -> TestMetricFilterResponse:
        raise NotImplementedError

    @handler("UntagLogGroup")
    def untag_log_group(
        self, context: RequestContext, log_group_name: LogGroupName, tags: TagList
    ) -> None:
        raise NotImplementedError

    @handler("UntagResource")
    def untag_resource(
        self, context: RequestContext, resource_arn: AmazonResourceName, tag_keys: TagKeyList
    ) -> None:
        raise NotImplementedError
