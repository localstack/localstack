from datetime import datetime
from enum import StrEnum
from typing import Dict, List, Optional, TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

AliasDescription = str
Arn = str
CharacterRestrictedName = str
ClientToken = str
ConnectorParameters = str
Definition = str
Enabled = bool
ErrorMessage = str
EvaluationFailureLocation = str
HTTPBody = str
HTTPHeaders = str
HTTPMethod = str
HTTPProtocol = str
HTTPStatusCode = str
HTTPStatusMessage = str
Identity = str
IncludeExecutionData = bool
IncludeExecutionDataGetExecutionHistory = bool
KmsDataKeyReusePeriodSeconds = int
KmsKeyId = str
ListExecutionsPageToken = str
LongArn = str
MapRunLabel = str
MaxConcurrency = int
Name = str
PageSize = int
PageToken = str
Publish = bool
RedriveCount = int
RevealSecrets = bool
ReverseOrder = bool
RevisionId = str
SensitiveCause = str
SensitiveData = str
SensitiveDataJobInput = str
SensitiveError = str
StateName = str
TagKey = str
TagValue = str
TaskToken = str
ToleratedFailurePercentage = float
TraceHeader = str
URL = str
UnsignedInteger = int
ValidateStateMachineDefinitionCode = str
ValidateStateMachineDefinitionLocation = str
ValidateStateMachineDefinitionMaxResult = int
ValidateStateMachineDefinitionMessage = str
ValidateStateMachineDefinitionTruncated = bool
VariableName = str
VariableValue = str
VersionDescription = str
VersionWeight = int
includedDetails = bool
truncated = bool


class EncryptionType(StrEnum):
    AWS_OWNED_KEY = "AWS_OWNED_KEY"
    CUSTOMER_MANAGED_KMS_KEY = "CUSTOMER_MANAGED_KMS_KEY"


class ExecutionRedriveFilter(StrEnum):
    REDRIVEN = "REDRIVEN"
    NOT_REDRIVEN = "NOT_REDRIVEN"


class ExecutionRedriveStatus(StrEnum):
    REDRIVABLE = "REDRIVABLE"
    NOT_REDRIVABLE = "NOT_REDRIVABLE"
    REDRIVABLE_BY_MAP_RUN = "REDRIVABLE_BY_MAP_RUN"


class ExecutionStatus(StrEnum):
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    TIMED_OUT = "TIMED_OUT"
    ABORTED = "ABORTED"
    PENDING_REDRIVE = "PENDING_REDRIVE"


class HistoryEventType(StrEnum):
    ActivityFailed = "ActivityFailed"
    ActivityScheduled = "ActivityScheduled"
    ActivityScheduleFailed = "ActivityScheduleFailed"
    ActivityStarted = "ActivityStarted"
    ActivitySucceeded = "ActivitySucceeded"
    ActivityTimedOut = "ActivityTimedOut"
    ChoiceStateEntered = "ChoiceStateEntered"
    ChoiceStateExited = "ChoiceStateExited"
    ExecutionAborted = "ExecutionAborted"
    ExecutionFailed = "ExecutionFailed"
    ExecutionStarted = "ExecutionStarted"
    ExecutionSucceeded = "ExecutionSucceeded"
    ExecutionTimedOut = "ExecutionTimedOut"
    FailStateEntered = "FailStateEntered"
    LambdaFunctionFailed = "LambdaFunctionFailed"
    LambdaFunctionScheduled = "LambdaFunctionScheduled"
    LambdaFunctionScheduleFailed = "LambdaFunctionScheduleFailed"
    LambdaFunctionStarted = "LambdaFunctionStarted"
    LambdaFunctionStartFailed = "LambdaFunctionStartFailed"
    LambdaFunctionSucceeded = "LambdaFunctionSucceeded"
    LambdaFunctionTimedOut = "LambdaFunctionTimedOut"
    MapIterationAborted = "MapIterationAborted"
    MapIterationFailed = "MapIterationFailed"
    MapIterationStarted = "MapIterationStarted"
    MapIterationSucceeded = "MapIterationSucceeded"
    MapStateAborted = "MapStateAborted"
    MapStateEntered = "MapStateEntered"
    MapStateExited = "MapStateExited"
    MapStateFailed = "MapStateFailed"
    MapStateStarted = "MapStateStarted"
    MapStateSucceeded = "MapStateSucceeded"
    ParallelStateAborted = "ParallelStateAborted"
    ParallelStateEntered = "ParallelStateEntered"
    ParallelStateExited = "ParallelStateExited"
    ParallelStateFailed = "ParallelStateFailed"
    ParallelStateStarted = "ParallelStateStarted"
    ParallelStateSucceeded = "ParallelStateSucceeded"
    PassStateEntered = "PassStateEntered"
    PassStateExited = "PassStateExited"
    SucceedStateEntered = "SucceedStateEntered"
    SucceedStateExited = "SucceedStateExited"
    TaskFailed = "TaskFailed"
    TaskScheduled = "TaskScheduled"
    TaskStarted = "TaskStarted"
    TaskStartFailed = "TaskStartFailed"
    TaskStateAborted = "TaskStateAborted"
    TaskStateEntered = "TaskStateEntered"
    TaskStateExited = "TaskStateExited"
    TaskSubmitFailed = "TaskSubmitFailed"
    TaskSubmitted = "TaskSubmitted"
    TaskSucceeded = "TaskSucceeded"
    TaskTimedOut = "TaskTimedOut"
    WaitStateAborted = "WaitStateAborted"
    WaitStateEntered = "WaitStateEntered"
    WaitStateExited = "WaitStateExited"
    MapRunAborted = "MapRunAborted"
    MapRunFailed = "MapRunFailed"
    MapRunStarted = "MapRunStarted"
    MapRunSucceeded = "MapRunSucceeded"
    ExecutionRedriven = "ExecutionRedriven"
    MapRunRedriven = "MapRunRedriven"
    EvaluationFailed = "EvaluationFailed"


class IncludedData(StrEnum):
    ALL_DATA = "ALL_DATA"
    METADATA_ONLY = "METADATA_ONLY"


class InspectionLevel(StrEnum):
    INFO = "INFO"
    DEBUG = "DEBUG"
    TRACE = "TRACE"


class KmsKeyState(StrEnum):
    DISABLED = "DISABLED"
    PENDING_DELETION = "PENDING_DELETION"
    PENDING_IMPORT = "PENDING_IMPORT"
    UNAVAILABLE = "UNAVAILABLE"
    CREATING = "CREATING"


class LogLevel(StrEnum):
    ALL = "ALL"
    ERROR = "ERROR"
    FATAL = "FATAL"
    OFF = "OFF"


class MapRunStatus(StrEnum):
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    ABORTED = "ABORTED"


class StateMachineStatus(StrEnum):
    ACTIVE = "ACTIVE"
    DELETING = "DELETING"


class StateMachineType(StrEnum):
    STANDARD = "STANDARD"
    EXPRESS = "EXPRESS"


class SyncExecutionStatus(StrEnum):
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    TIMED_OUT = "TIMED_OUT"


class TestExecutionStatus(StrEnum):
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    RETRIABLE = "RETRIABLE"
    CAUGHT_ERROR = "CAUGHT_ERROR"


class ValidateStateMachineDefinitionResultCode(StrEnum):
    OK = "OK"
    FAIL = "FAIL"


class ValidateStateMachineDefinitionSeverity(StrEnum):
    ERROR = "ERROR"
    WARNING = "WARNING"


class ValidationExceptionReason(StrEnum):
    API_DOES_NOT_SUPPORT_LABELED_ARNS = "API_DOES_NOT_SUPPORT_LABELED_ARNS"
    MISSING_REQUIRED_PARAMETER = "MISSING_REQUIRED_PARAMETER"
    CANNOT_UPDATE_COMPLETED_MAP_RUN = "CANNOT_UPDATE_COMPLETED_MAP_RUN"
    INVALID_ROUTING_CONFIGURATION = "INVALID_ROUTING_CONFIGURATION"


class ActivityAlreadyExists(ServiceException):
    code: str = "ActivityAlreadyExists"
    sender_fault: bool = False
    status_code: int = 400


class ActivityDoesNotExist(ServiceException):
    code: str = "ActivityDoesNotExist"
    sender_fault: bool = False
    status_code: int = 400


class ActivityLimitExceeded(ServiceException):
    code: str = "ActivityLimitExceeded"
    sender_fault: bool = False
    status_code: int = 400


class ActivityWorkerLimitExceeded(ServiceException):
    code: str = "ActivityWorkerLimitExceeded"
    sender_fault: bool = False
    status_code: int = 400


class ConflictException(ServiceException):
    code: str = "ConflictException"
    sender_fault: bool = False
    status_code: int = 400


class ExecutionAlreadyExists(ServiceException):
    code: str = "ExecutionAlreadyExists"
    sender_fault: bool = False
    status_code: int = 400


class ExecutionDoesNotExist(ServiceException):
    code: str = "ExecutionDoesNotExist"
    sender_fault: bool = False
    status_code: int = 400


class ExecutionLimitExceeded(ServiceException):
    code: str = "ExecutionLimitExceeded"
    sender_fault: bool = False
    status_code: int = 400


class ExecutionNotRedrivable(ServiceException):
    code: str = "ExecutionNotRedrivable"
    sender_fault: bool = False
    status_code: int = 400


class InvalidArn(ServiceException):
    code: str = "InvalidArn"
    sender_fault: bool = False
    status_code: int = 400


class InvalidDefinition(ServiceException):
    code: str = "InvalidDefinition"
    sender_fault: bool = False
    status_code: int = 400


class InvalidEncryptionConfiguration(ServiceException):
    code: str = "InvalidEncryptionConfiguration"
    sender_fault: bool = False
    status_code: int = 400


class InvalidExecutionInput(ServiceException):
    code: str = "InvalidExecutionInput"
    sender_fault: bool = False
    status_code: int = 400


class InvalidLoggingConfiguration(ServiceException):
    code: str = "InvalidLoggingConfiguration"
    sender_fault: bool = False
    status_code: int = 400


class InvalidName(ServiceException):
    code: str = "InvalidName"
    sender_fault: bool = False
    status_code: int = 400


class InvalidOutput(ServiceException):
    code: str = "InvalidOutput"
    sender_fault: bool = False
    status_code: int = 400


class InvalidToken(ServiceException):
    code: str = "InvalidToken"
    sender_fault: bool = False
    status_code: int = 400


class InvalidTracingConfiguration(ServiceException):
    code: str = "InvalidTracingConfiguration"
    sender_fault: bool = False
    status_code: int = 400


class KmsAccessDeniedException(ServiceException):
    code: str = "KmsAccessDeniedException"
    sender_fault: bool = False
    status_code: int = 400


class KmsInvalidStateException(ServiceException):
    code: str = "KmsInvalidStateException"
    sender_fault: bool = False
    status_code: int = 400
    kmsKeyState: Optional[KmsKeyState]


class KmsThrottlingException(ServiceException):
    code: str = "KmsThrottlingException"
    sender_fault: bool = False
    status_code: int = 400


class MissingRequiredParameter(ServiceException):
    code: str = "MissingRequiredParameter"
    sender_fault: bool = False
    status_code: int = 400


class ResourceNotFound(ServiceException):
    code: str = "ResourceNotFound"
    sender_fault: bool = False
    status_code: int = 400
    resourceName: Optional[Arn]


class ServiceQuotaExceededException(ServiceException):
    code: str = "ServiceQuotaExceededException"
    sender_fault: bool = False
    status_code: int = 400


class StateMachineAlreadyExists(ServiceException):
    code: str = "StateMachineAlreadyExists"
    sender_fault: bool = False
    status_code: int = 400


class StateMachineDeleting(ServiceException):
    code: str = "StateMachineDeleting"
    sender_fault: bool = False
    status_code: int = 400


class StateMachineDoesNotExist(ServiceException):
    code: str = "StateMachineDoesNotExist"
    sender_fault: bool = False
    status_code: int = 400


class StateMachineLimitExceeded(ServiceException):
    code: str = "StateMachineLimitExceeded"
    sender_fault: bool = False
    status_code: int = 400


class StateMachineTypeNotSupported(ServiceException):
    code: str = "StateMachineTypeNotSupported"
    sender_fault: bool = False
    status_code: int = 400


class TaskDoesNotExist(ServiceException):
    code: str = "TaskDoesNotExist"
    sender_fault: bool = False
    status_code: int = 400


class TaskTimedOut(ServiceException):
    code: str = "TaskTimedOut"
    sender_fault: bool = False
    status_code: int = 400


class TooManyTags(ServiceException):
    code: str = "TooManyTags"
    sender_fault: bool = False
    status_code: int = 400
    resourceName: Optional[Arn]


class ValidationException(ServiceException):
    code: str = "ValidationException"
    sender_fault: bool = False
    status_code: int = 400
    reason: Optional[ValidationExceptionReason]


class ActivityFailedEventDetails(TypedDict, total=False):
    error: Optional[SensitiveError]
    cause: Optional[SensitiveCause]


Timestamp = datetime


class ActivityListItem(TypedDict, total=False):
    activityArn: Arn
    name: Name
    creationDate: Timestamp


ActivityList = List[ActivityListItem]


class ActivityScheduleFailedEventDetails(TypedDict, total=False):
    error: Optional[SensitiveError]
    cause: Optional[SensitiveCause]


TimeoutInSeconds = int


class HistoryEventExecutionDataDetails(TypedDict, total=False):
    truncated: Optional[truncated]


class ActivityScheduledEventDetails(TypedDict, total=False):
    resource: Arn
    input: Optional[SensitiveData]
    inputDetails: Optional[HistoryEventExecutionDataDetails]
    timeoutInSeconds: Optional[TimeoutInSeconds]
    heartbeatInSeconds: Optional[TimeoutInSeconds]


class ActivityStartedEventDetails(TypedDict, total=False):
    workerName: Optional[Identity]


class ActivitySucceededEventDetails(TypedDict, total=False):
    output: Optional[SensitiveData]
    outputDetails: Optional[HistoryEventExecutionDataDetails]


class ActivityTimedOutEventDetails(TypedDict, total=False):
    error: Optional[SensitiveError]
    cause: Optional[SensitiveCause]


AssignedVariables = Dict[VariableName, VariableValue]


class AssignedVariablesDetails(TypedDict, total=False):
    truncated: Optional[truncated]


BilledDuration = int
BilledMemoryUsed = int


class BillingDetails(TypedDict, total=False):
    billedMemoryUsedInMB: Optional[BilledMemoryUsed]
    billedDurationInMilliseconds: Optional[BilledDuration]


class CloudWatchEventsExecutionDataDetails(TypedDict, total=False):
    included: Optional[includedDetails]


class CloudWatchLogsLogGroup(TypedDict, total=False):
    logGroupArn: Optional[Arn]


EncryptionConfiguration = TypedDict(
    "EncryptionConfiguration",
    {
        "kmsKeyId": Optional[KmsKeyId],
        "kmsDataKeyReusePeriodSeconds": Optional[KmsDataKeyReusePeriodSeconds],
        "type": EncryptionType,
    },
    total=False,
)


class Tag(TypedDict, total=False):
    key: Optional[TagKey]
    value: Optional[TagValue]


TagList = List[Tag]


class CreateActivityInput(ServiceRequest):
    name: Name
    tags: Optional[TagList]
    encryptionConfiguration: Optional[EncryptionConfiguration]


class CreateActivityOutput(TypedDict, total=False):
    activityArn: Arn
    creationDate: Timestamp


class RoutingConfigurationListItem(TypedDict, total=False):
    stateMachineVersionArn: Arn
    weight: VersionWeight


RoutingConfigurationList = List[RoutingConfigurationListItem]


class CreateStateMachineAliasInput(ServiceRequest):
    description: Optional[AliasDescription]
    name: CharacterRestrictedName
    routingConfiguration: RoutingConfigurationList


class CreateStateMachineAliasOutput(TypedDict, total=False):
    stateMachineAliasArn: Arn
    creationDate: Timestamp


class TracingConfiguration(TypedDict, total=False):
    enabled: Optional[Enabled]


class LogDestination(TypedDict, total=False):
    cloudWatchLogsLogGroup: Optional[CloudWatchLogsLogGroup]


LogDestinationList = List[LogDestination]


class LoggingConfiguration(TypedDict, total=False):
    level: Optional[LogLevel]
    includeExecutionData: Optional[IncludeExecutionData]
    destinations: Optional[LogDestinationList]


CreateStateMachineInput = TypedDict(
    "CreateStateMachineInput",
    {
        "name": Name,
        "definition": Definition,
        "roleArn": Arn,
        "type": Optional[StateMachineType],
        "loggingConfiguration": Optional[LoggingConfiguration],
        "tags": Optional[TagList],
        "tracingConfiguration": Optional[TracingConfiguration],
        "publish": Optional[Publish],
        "versionDescription": Optional[VersionDescription],
        "encryptionConfiguration": Optional[EncryptionConfiguration],
    },
    total=False,
)


class CreateStateMachineOutput(TypedDict, total=False):
    stateMachineArn: Arn
    creationDate: Timestamp
    stateMachineVersionArn: Optional[Arn]


class DeleteActivityInput(ServiceRequest):
    activityArn: Arn


class DeleteActivityOutput(TypedDict, total=False):
    pass


class DeleteStateMachineAliasInput(ServiceRequest):
    stateMachineAliasArn: Arn


class DeleteStateMachineAliasOutput(TypedDict, total=False):
    pass


class DeleteStateMachineInput(ServiceRequest):
    stateMachineArn: Arn


class DeleteStateMachineOutput(TypedDict, total=False):
    pass


class DeleteStateMachineVersionInput(ServiceRequest):
    stateMachineVersionArn: LongArn


class DeleteStateMachineVersionOutput(TypedDict, total=False):
    pass


class DescribeActivityInput(ServiceRequest):
    activityArn: Arn


class DescribeActivityOutput(TypedDict, total=False):
    activityArn: Arn
    name: Name
    creationDate: Timestamp
    encryptionConfiguration: Optional[EncryptionConfiguration]


class DescribeExecutionInput(ServiceRequest):
    executionArn: Arn
    includedData: Optional[IncludedData]


class DescribeExecutionOutput(TypedDict, total=False):
    executionArn: Arn
    stateMachineArn: Arn
    name: Optional[Name]
    status: ExecutionStatus
    startDate: Timestamp
    stopDate: Optional[Timestamp]
    input: Optional[SensitiveData]
    inputDetails: Optional[CloudWatchEventsExecutionDataDetails]
    output: Optional[SensitiveData]
    outputDetails: Optional[CloudWatchEventsExecutionDataDetails]
    traceHeader: Optional[TraceHeader]
    mapRunArn: Optional[LongArn]
    error: Optional[SensitiveError]
    cause: Optional[SensitiveCause]
    stateMachineVersionArn: Optional[Arn]
    stateMachineAliasArn: Optional[Arn]
    redriveCount: Optional[RedriveCount]
    redriveDate: Optional[Timestamp]
    redriveStatus: Optional[ExecutionRedriveStatus]
    redriveStatusReason: Optional[SensitiveData]


class DescribeMapRunInput(ServiceRequest):
    mapRunArn: LongArn


LongObject = int
UnsignedLong = int


class MapRunExecutionCounts(TypedDict, total=False):
    pending: UnsignedLong
    running: UnsignedLong
    succeeded: UnsignedLong
    failed: UnsignedLong
    timedOut: UnsignedLong
    aborted: UnsignedLong
    total: UnsignedLong
    resultsWritten: UnsignedLong
    failuresNotRedrivable: Optional[LongObject]
    pendingRedrive: Optional[LongObject]


class MapRunItemCounts(TypedDict, total=False):
    pending: UnsignedLong
    running: UnsignedLong
    succeeded: UnsignedLong
    failed: UnsignedLong
    timedOut: UnsignedLong
    aborted: UnsignedLong
    total: UnsignedLong
    resultsWritten: UnsignedLong
    failuresNotRedrivable: Optional[LongObject]
    pendingRedrive: Optional[LongObject]


ToleratedFailureCount = int


class DescribeMapRunOutput(TypedDict, total=False):
    mapRunArn: LongArn
    executionArn: Arn
    status: MapRunStatus
    startDate: Timestamp
    stopDate: Optional[Timestamp]
    maxConcurrency: MaxConcurrency
    toleratedFailurePercentage: ToleratedFailurePercentage
    toleratedFailureCount: ToleratedFailureCount
    itemCounts: MapRunItemCounts
    executionCounts: MapRunExecutionCounts
    redriveCount: Optional[RedriveCount]
    redriveDate: Optional[Timestamp]


class DescribeStateMachineAliasInput(ServiceRequest):
    stateMachineAliasArn: Arn


class DescribeStateMachineAliasOutput(TypedDict, total=False):
    stateMachineAliasArn: Optional[Arn]
    name: Optional[Name]
    description: Optional[AliasDescription]
    routingConfiguration: Optional[RoutingConfigurationList]
    creationDate: Optional[Timestamp]
    updateDate: Optional[Timestamp]


class DescribeStateMachineForExecutionInput(ServiceRequest):
    executionArn: Arn
    includedData: Optional[IncludedData]


VariableNameList = List[VariableName]
VariableReferences = Dict[StateName, VariableNameList]


class DescribeStateMachineForExecutionOutput(TypedDict, total=False):
    stateMachineArn: Arn
    name: Name
    definition: Definition
    roleArn: Arn
    updateDate: Timestamp
    loggingConfiguration: Optional[LoggingConfiguration]
    tracingConfiguration: Optional[TracingConfiguration]
    mapRunArn: Optional[LongArn]
    label: Optional[MapRunLabel]
    revisionId: Optional[RevisionId]
    encryptionConfiguration: Optional[EncryptionConfiguration]
    variableReferences: Optional[VariableReferences]


class DescribeStateMachineInput(ServiceRequest):
    stateMachineArn: Arn
    includedData: Optional[IncludedData]


DescribeStateMachineOutput = TypedDict(
    "DescribeStateMachineOutput",
    {
        "stateMachineArn": Arn,
        "name": Name,
        "status": Optional[StateMachineStatus],
        "definition": Definition,
        "roleArn": Arn,
        "type": StateMachineType,
        "creationDate": Timestamp,
        "loggingConfiguration": Optional[LoggingConfiguration],
        "tracingConfiguration": Optional[TracingConfiguration],
        "label": Optional[MapRunLabel],
        "revisionId": Optional[RevisionId],
        "description": Optional[VersionDescription],
        "encryptionConfiguration": Optional[EncryptionConfiguration],
        "variableReferences": Optional[VariableReferences],
    },
    total=False,
)


class EvaluationFailedEventDetails(TypedDict, total=False):
    error: Optional[SensitiveError]
    cause: Optional[SensitiveCause]
    location: Optional[EvaluationFailureLocation]
    state: StateName


EventId = int


class ExecutionAbortedEventDetails(TypedDict, total=False):
    error: Optional[SensitiveError]
    cause: Optional[SensitiveCause]


class ExecutionFailedEventDetails(TypedDict, total=False):
    error: Optional[SensitiveError]
    cause: Optional[SensitiveCause]


class ExecutionListItem(TypedDict, total=False):
    executionArn: Arn
    stateMachineArn: Arn
    name: Name
    status: ExecutionStatus
    startDate: Timestamp
    stopDate: Optional[Timestamp]
    mapRunArn: Optional[LongArn]
    itemCount: Optional[UnsignedInteger]
    stateMachineVersionArn: Optional[Arn]
    stateMachineAliasArn: Optional[Arn]
    redriveCount: Optional[RedriveCount]
    redriveDate: Optional[Timestamp]


ExecutionList = List[ExecutionListItem]


class ExecutionRedrivenEventDetails(TypedDict, total=False):
    redriveCount: Optional[RedriveCount]


class ExecutionStartedEventDetails(TypedDict, total=False):
    input: Optional[SensitiveData]
    inputDetails: Optional[HistoryEventExecutionDataDetails]
    roleArn: Optional[Arn]
    stateMachineAliasArn: Optional[Arn]
    stateMachineVersionArn: Optional[Arn]


class ExecutionSucceededEventDetails(TypedDict, total=False):
    output: Optional[SensitiveData]
    outputDetails: Optional[HistoryEventExecutionDataDetails]


class ExecutionTimedOutEventDetails(TypedDict, total=False):
    error: Optional[SensitiveError]
    cause: Optional[SensitiveCause]


class GetActivityTaskInput(ServiceRequest):
    activityArn: Arn
    workerName: Optional[Name]


class GetActivityTaskOutput(TypedDict, total=False):
    taskToken: Optional[TaskToken]
    input: Optional[SensitiveDataJobInput]


class GetExecutionHistoryInput(ServiceRequest):
    executionArn: Arn
    maxResults: Optional[PageSize]
    reverseOrder: Optional[ReverseOrder]
    nextToken: Optional[PageToken]
    includeExecutionData: Optional[IncludeExecutionDataGetExecutionHistory]


class MapRunRedrivenEventDetails(TypedDict, total=False):
    mapRunArn: Optional[LongArn]
    redriveCount: Optional[RedriveCount]


class MapRunFailedEventDetails(TypedDict, total=False):
    error: Optional[SensitiveError]
    cause: Optional[SensitiveCause]


class MapRunStartedEventDetails(TypedDict, total=False):
    mapRunArn: Optional[LongArn]


class StateExitedEventDetails(TypedDict, total=False):
    name: Name
    output: Optional[SensitiveData]
    outputDetails: Optional[HistoryEventExecutionDataDetails]
    assignedVariables: Optional[AssignedVariables]
    assignedVariablesDetails: Optional[AssignedVariablesDetails]


class StateEnteredEventDetails(TypedDict, total=False):
    name: Name
    input: Optional[SensitiveData]
    inputDetails: Optional[HistoryEventExecutionDataDetails]


class LambdaFunctionTimedOutEventDetails(TypedDict, total=False):
    error: Optional[SensitiveError]
    cause: Optional[SensitiveCause]


class LambdaFunctionSucceededEventDetails(TypedDict, total=False):
    output: Optional[SensitiveData]
    outputDetails: Optional[HistoryEventExecutionDataDetails]


class LambdaFunctionStartFailedEventDetails(TypedDict, total=False):
    error: Optional[SensitiveError]
    cause: Optional[SensitiveCause]


class TaskCredentials(TypedDict, total=False):
    roleArn: Optional[LongArn]


class LambdaFunctionScheduledEventDetails(TypedDict, total=False):
    resource: Arn
    input: Optional[SensitiveData]
    inputDetails: Optional[HistoryEventExecutionDataDetails]
    timeoutInSeconds: Optional[TimeoutInSeconds]
    taskCredentials: Optional[TaskCredentials]


class LambdaFunctionScheduleFailedEventDetails(TypedDict, total=False):
    error: Optional[SensitiveError]
    cause: Optional[SensitiveCause]


class LambdaFunctionFailedEventDetails(TypedDict, total=False):
    error: Optional[SensitiveError]
    cause: Optional[SensitiveCause]


class MapIterationEventDetails(TypedDict, total=False):
    name: Optional[Name]
    index: Optional[UnsignedInteger]


class MapStateStartedEventDetails(TypedDict, total=False):
    length: Optional[UnsignedInteger]


class TaskTimedOutEventDetails(TypedDict, total=False):
    resourceType: Name
    resource: Name
    error: Optional[SensitiveError]
    cause: Optional[SensitiveCause]


class TaskSucceededEventDetails(TypedDict, total=False):
    resourceType: Name
    resource: Name
    output: Optional[SensitiveData]
    outputDetails: Optional[HistoryEventExecutionDataDetails]


class TaskSubmittedEventDetails(TypedDict, total=False):
    resourceType: Name
    resource: Name
    output: Optional[SensitiveData]
    outputDetails: Optional[HistoryEventExecutionDataDetails]


class TaskSubmitFailedEventDetails(TypedDict, total=False):
    resourceType: Name
    resource: Name
    error: Optional[SensitiveError]
    cause: Optional[SensitiveCause]


class TaskStartedEventDetails(TypedDict, total=False):
    resourceType: Name
    resource: Name


class TaskStartFailedEventDetails(TypedDict, total=False):
    resourceType: Name
    resource: Name
    error: Optional[SensitiveError]
    cause: Optional[SensitiveCause]


class TaskScheduledEventDetails(TypedDict, total=False):
    resourceType: Name
    resource: Name
    region: Name
    parameters: ConnectorParameters
    timeoutInSeconds: Optional[TimeoutInSeconds]
    heartbeatInSeconds: Optional[TimeoutInSeconds]
    taskCredentials: Optional[TaskCredentials]


class TaskFailedEventDetails(TypedDict, total=False):
    resourceType: Name
    resource: Name
    error: Optional[SensitiveError]
    cause: Optional[SensitiveCause]


HistoryEvent = TypedDict(
    "HistoryEvent",
    {
        "timestamp": Timestamp,
        "type": HistoryEventType,
        "id": EventId,
        "previousEventId": Optional[EventId],
        "activityFailedEventDetails": Optional[ActivityFailedEventDetails],
        "activityScheduleFailedEventDetails": Optional[ActivityScheduleFailedEventDetails],
        "activityScheduledEventDetails": Optional[ActivityScheduledEventDetails],
        "activityStartedEventDetails": Optional[ActivityStartedEventDetails],
        "activitySucceededEventDetails": Optional[ActivitySucceededEventDetails],
        "activityTimedOutEventDetails": Optional[ActivityTimedOutEventDetails],
        "taskFailedEventDetails": Optional[TaskFailedEventDetails],
        "taskScheduledEventDetails": Optional[TaskScheduledEventDetails],
        "taskStartFailedEventDetails": Optional[TaskStartFailedEventDetails],
        "taskStartedEventDetails": Optional[TaskStartedEventDetails],
        "taskSubmitFailedEventDetails": Optional[TaskSubmitFailedEventDetails],
        "taskSubmittedEventDetails": Optional[TaskSubmittedEventDetails],
        "taskSucceededEventDetails": Optional[TaskSucceededEventDetails],
        "taskTimedOutEventDetails": Optional[TaskTimedOutEventDetails],
        "executionFailedEventDetails": Optional[ExecutionFailedEventDetails],
        "executionStartedEventDetails": Optional[ExecutionStartedEventDetails],
        "executionSucceededEventDetails": Optional[ExecutionSucceededEventDetails],
        "executionAbortedEventDetails": Optional[ExecutionAbortedEventDetails],
        "executionTimedOutEventDetails": Optional[ExecutionTimedOutEventDetails],
        "executionRedrivenEventDetails": Optional[ExecutionRedrivenEventDetails],
        "mapStateStartedEventDetails": Optional[MapStateStartedEventDetails],
        "mapIterationStartedEventDetails": Optional[MapIterationEventDetails],
        "mapIterationSucceededEventDetails": Optional[MapIterationEventDetails],
        "mapIterationFailedEventDetails": Optional[MapIterationEventDetails],
        "mapIterationAbortedEventDetails": Optional[MapIterationEventDetails],
        "lambdaFunctionFailedEventDetails": Optional[LambdaFunctionFailedEventDetails],
        "lambdaFunctionScheduleFailedEventDetails": Optional[
            LambdaFunctionScheduleFailedEventDetails
        ],
        "lambdaFunctionScheduledEventDetails": Optional[LambdaFunctionScheduledEventDetails],
        "lambdaFunctionStartFailedEventDetails": Optional[LambdaFunctionStartFailedEventDetails],
        "lambdaFunctionSucceededEventDetails": Optional[LambdaFunctionSucceededEventDetails],
        "lambdaFunctionTimedOutEventDetails": Optional[LambdaFunctionTimedOutEventDetails],
        "stateEnteredEventDetails": Optional[StateEnteredEventDetails],
        "stateExitedEventDetails": Optional[StateExitedEventDetails],
        "mapRunStartedEventDetails": Optional[MapRunStartedEventDetails],
        "mapRunFailedEventDetails": Optional[MapRunFailedEventDetails],
        "mapRunRedrivenEventDetails": Optional[MapRunRedrivenEventDetails],
        "evaluationFailedEventDetails": Optional[EvaluationFailedEventDetails],
    },
    total=False,
)
HistoryEventList = List[HistoryEvent]


class GetExecutionHistoryOutput(TypedDict, total=False):
    events: HistoryEventList
    nextToken: Optional[PageToken]


class InspectionDataResponse(TypedDict, total=False):
    protocol: Optional[HTTPProtocol]
    statusCode: Optional[HTTPStatusCode]
    statusMessage: Optional[HTTPStatusMessage]
    headers: Optional[HTTPHeaders]
    body: Optional[HTTPBody]


class InspectionDataRequest(TypedDict, total=False):
    protocol: Optional[HTTPProtocol]
    method: Optional[HTTPMethod]
    url: Optional[URL]
    headers: Optional[HTTPHeaders]
    body: Optional[HTTPBody]


class InspectionData(TypedDict, total=False):
    input: Optional[SensitiveData]
    afterArguments: Optional[SensitiveData]
    afterInputPath: Optional[SensitiveData]
    afterParameters: Optional[SensitiveData]
    result: Optional[SensitiveData]
    afterResultSelector: Optional[SensitiveData]
    afterResultPath: Optional[SensitiveData]
    request: Optional[InspectionDataRequest]
    response: Optional[InspectionDataResponse]
    variables: Optional[SensitiveData]


class ListActivitiesInput(ServiceRequest):
    maxResults: Optional[PageSize]
    nextToken: Optional[PageToken]


class ListActivitiesOutput(TypedDict, total=False):
    activities: ActivityList
    nextToken: Optional[PageToken]


class ListExecutionsInput(ServiceRequest):
    stateMachineArn: Optional[Arn]
    statusFilter: Optional[ExecutionStatus]
    maxResults: Optional[PageSize]
    nextToken: Optional[ListExecutionsPageToken]
    mapRunArn: Optional[LongArn]
    redriveFilter: Optional[ExecutionRedriveFilter]


class ListExecutionsOutput(TypedDict, total=False):
    executions: ExecutionList
    nextToken: Optional[ListExecutionsPageToken]


class ListMapRunsInput(ServiceRequest):
    executionArn: Arn
    maxResults: Optional[PageSize]
    nextToken: Optional[PageToken]


class MapRunListItem(TypedDict, total=False):
    executionArn: Arn
    mapRunArn: LongArn
    stateMachineArn: Arn
    startDate: Timestamp
    stopDate: Optional[Timestamp]


MapRunList = List[MapRunListItem]


class ListMapRunsOutput(TypedDict, total=False):
    mapRuns: MapRunList
    nextToken: Optional[PageToken]


class ListStateMachineAliasesInput(ServiceRequest):
    stateMachineArn: Arn
    nextToken: Optional[PageToken]
    maxResults: Optional[PageSize]


class StateMachineAliasListItem(TypedDict, total=False):
    stateMachineAliasArn: LongArn
    creationDate: Timestamp


StateMachineAliasList = List[StateMachineAliasListItem]


class ListStateMachineAliasesOutput(TypedDict, total=False):
    stateMachineAliases: StateMachineAliasList
    nextToken: Optional[PageToken]


class ListStateMachineVersionsInput(ServiceRequest):
    stateMachineArn: Arn
    nextToken: Optional[PageToken]
    maxResults: Optional[PageSize]


class StateMachineVersionListItem(TypedDict, total=False):
    stateMachineVersionArn: LongArn
    creationDate: Timestamp


StateMachineVersionList = List[StateMachineVersionListItem]


class ListStateMachineVersionsOutput(TypedDict, total=False):
    stateMachineVersions: StateMachineVersionList
    nextToken: Optional[PageToken]


class ListStateMachinesInput(ServiceRequest):
    maxResults: Optional[PageSize]
    nextToken: Optional[PageToken]


StateMachineListItem = TypedDict(
    "StateMachineListItem",
    {
        "stateMachineArn": Arn,
        "name": Name,
        "type": StateMachineType,
        "creationDate": Timestamp,
    },
    total=False,
)
StateMachineList = List[StateMachineListItem]


class ListStateMachinesOutput(TypedDict, total=False):
    stateMachines: StateMachineList
    nextToken: Optional[PageToken]


class ListTagsForResourceInput(ServiceRequest):
    resourceArn: Arn


class ListTagsForResourceOutput(TypedDict, total=False):
    tags: Optional[TagList]


class PublishStateMachineVersionInput(ServiceRequest):
    stateMachineArn: Arn
    revisionId: Optional[RevisionId]
    description: Optional[VersionDescription]


class PublishStateMachineVersionOutput(TypedDict, total=False):
    creationDate: Timestamp
    stateMachineVersionArn: Arn


class RedriveExecutionInput(ServiceRequest):
    executionArn: Arn
    clientToken: Optional[ClientToken]


class RedriveExecutionOutput(TypedDict, total=False):
    redriveDate: Timestamp


class SendTaskFailureInput(ServiceRequest):
    taskToken: TaskToken
    error: Optional[SensitiveError]
    cause: Optional[SensitiveCause]


class SendTaskFailureOutput(TypedDict, total=False):
    pass


class SendTaskHeartbeatInput(ServiceRequest):
    taskToken: TaskToken


class SendTaskHeartbeatOutput(TypedDict, total=False):
    pass


class SendTaskSuccessInput(ServiceRequest):
    taskToken: TaskToken
    output: SensitiveData


class SendTaskSuccessOutput(TypedDict, total=False):
    pass


class StartExecutionInput(ServiceRequest):
    stateMachineArn: Arn
    name: Optional[Name]
    input: Optional[SensitiveData]
    traceHeader: Optional[TraceHeader]


class StartExecutionOutput(TypedDict, total=False):
    executionArn: Arn
    startDate: Timestamp


class StartSyncExecutionInput(ServiceRequest):
    stateMachineArn: Arn
    name: Optional[Name]
    input: Optional[SensitiveData]
    traceHeader: Optional[TraceHeader]
    includedData: Optional[IncludedData]


class StartSyncExecutionOutput(TypedDict, total=False):
    executionArn: Arn
    stateMachineArn: Optional[Arn]
    name: Optional[Name]
    startDate: Timestamp
    stopDate: Timestamp
    status: SyncExecutionStatus
    error: Optional[SensitiveError]
    cause: Optional[SensitiveCause]
    input: Optional[SensitiveData]
    inputDetails: Optional[CloudWatchEventsExecutionDataDetails]
    output: Optional[SensitiveData]
    outputDetails: Optional[CloudWatchEventsExecutionDataDetails]
    traceHeader: Optional[TraceHeader]
    billingDetails: Optional[BillingDetails]


class StopExecutionInput(ServiceRequest):
    executionArn: Arn
    error: Optional[SensitiveError]
    cause: Optional[SensitiveCause]


class StopExecutionOutput(TypedDict, total=False):
    stopDate: Timestamp


TagKeyList = List[TagKey]


class TagResourceInput(ServiceRequest):
    resourceArn: Arn
    tags: TagList


class TagResourceOutput(TypedDict, total=False):
    pass


class TestStateInput(ServiceRequest):
    definition: Definition
    roleArn: Optional[Arn]
    input: Optional[SensitiveData]
    inspectionLevel: Optional[InspectionLevel]
    revealSecrets: Optional[RevealSecrets]
    variables: Optional[SensitiveData]


class TestStateOutput(TypedDict, total=False):
    output: Optional[SensitiveData]
    error: Optional[SensitiveError]
    cause: Optional[SensitiveCause]
    inspectionData: Optional[InspectionData]
    nextState: Optional[StateName]
    status: Optional[TestExecutionStatus]


class UntagResourceInput(ServiceRequest):
    resourceArn: Arn
    tagKeys: TagKeyList


class UntagResourceOutput(TypedDict, total=False):
    pass


class UpdateMapRunInput(ServiceRequest):
    mapRunArn: LongArn
    maxConcurrency: Optional[MaxConcurrency]
    toleratedFailurePercentage: Optional[ToleratedFailurePercentage]
    toleratedFailureCount: Optional[ToleratedFailureCount]


class UpdateMapRunOutput(TypedDict, total=False):
    pass


class UpdateStateMachineAliasInput(ServiceRequest):
    stateMachineAliasArn: Arn
    description: Optional[AliasDescription]
    routingConfiguration: Optional[RoutingConfigurationList]


class UpdateStateMachineAliasOutput(TypedDict, total=False):
    updateDate: Timestamp


class UpdateStateMachineInput(ServiceRequest):
    stateMachineArn: Arn
    definition: Optional[Definition]
    roleArn: Optional[Arn]
    loggingConfiguration: Optional[LoggingConfiguration]
    tracingConfiguration: Optional[TracingConfiguration]
    publish: Optional[Publish]
    versionDescription: Optional[VersionDescription]
    encryptionConfiguration: Optional[EncryptionConfiguration]


class UpdateStateMachineOutput(TypedDict, total=False):
    updateDate: Timestamp
    revisionId: Optional[RevisionId]
    stateMachineVersionArn: Optional[Arn]


class ValidateStateMachineDefinitionDiagnostic(TypedDict, total=False):
    severity: ValidateStateMachineDefinitionSeverity
    code: ValidateStateMachineDefinitionCode
    message: ValidateStateMachineDefinitionMessage
    location: Optional[ValidateStateMachineDefinitionLocation]


ValidateStateMachineDefinitionDiagnosticList = List[ValidateStateMachineDefinitionDiagnostic]
ValidateStateMachineDefinitionInput = TypedDict(
    "ValidateStateMachineDefinitionInput",
    {
        "definition": Definition,
        "type": Optional[StateMachineType],
        "severity": Optional[ValidateStateMachineDefinitionSeverity],
        "maxResults": Optional[ValidateStateMachineDefinitionMaxResult],
    },
    total=False,
)


class ValidateStateMachineDefinitionOutput(TypedDict, total=False):
    result: ValidateStateMachineDefinitionResultCode
    diagnostics: ValidateStateMachineDefinitionDiagnosticList
    truncated: Optional[ValidateStateMachineDefinitionTruncated]


class StepfunctionsApi:
    service = "stepfunctions"
    version = "2016-11-23"

    @handler("CreateActivity")
    def create_activity(
        self,
        context: RequestContext,
        name: Name,
        tags: TagList | None = None,
        encryption_configuration: EncryptionConfiguration | None = None,
        **kwargs,
    ) -> CreateActivityOutput:
        raise NotImplementedError

    @handler("CreateStateMachine", expand=False)
    def create_state_machine(
        self, context: RequestContext, request: CreateStateMachineInput, **kwargs
    ) -> CreateStateMachineOutput:
        raise NotImplementedError

    @handler("CreateStateMachineAlias")
    def create_state_machine_alias(
        self,
        context: RequestContext,
        name: CharacterRestrictedName,
        routing_configuration: RoutingConfigurationList,
        description: AliasDescription | None = None,
        **kwargs,
    ) -> CreateStateMachineAliasOutput:
        raise NotImplementedError

    @handler("DeleteActivity")
    def delete_activity(
        self, context: RequestContext, activity_arn: Arn, **kwargs
    ) -> DeleteActivityOutput:
        raise NotImplementedError

    @handler("DeleteStateMachine")
    def delete_state_machine(
        self, context: RequestContext, state_machine_arn: Arn, **kwargs
    ) -> DeleteStateMachineOutput:
        raise NotImplementedError

    @handler("DeleteStateMachineAlias")
    def delete_state_machine_alias(
        self, context: RequestContext, state_machine_alias_arn: Arn, **kwargs
    ) -> DeleteStateMachineAliasOutput:
        raise NotImplementedError

    @handler("DeleteStateMachineVersion")
    def delete_state_machine_version(
        self, context: RequestContext, state_machine_version_arn: LongArn, **kwargs
    ) -> DeleteStateMachineVersionOutput:
        raise NotImplementedError

    @handler("DescribeActivity")
    def describe_activity(
        self, context: RequestContext, activity_arn: Arn, **kwargs
    ) -> DescribeActivityOutput:
        raise NotImplementedError

    @handler("DescribeExecution")
    def describe_execution(
        self,
        context: RequestContext,
        execution_arn: Arn,
        included_data: IncludedData | None = None,
        **kwargs,
    ) -> DescribeExecutionOutput:
        raise NotImplementedError

    @handler("DescribeMapRun")
    def describe_map_run(
        self, context: RequestContext, map_run_arn: LongArn, **kwargs
    ) -> DescribeMapRunOutput:
        raise NotImplementedError

    @handler("DescribeStateMachine")
    def describe_state_machine(
        self,
        context: RequestContext,
        state_machine_arn: Arn,
        included_data: IncludedData | None = None,
        **kwargs,
    ) -> DescribeStateMachineOutput:
        raise NotImplementedError

    @handler("DescribeStateMachineAlias")
    def describe_state_machine_alias(
        self, context: RequestContext, state_machine_alias_arn: Arn, **kwargs
    ) -> DescribeStateMachineAliasOutput:
        raise NotImplementedError

    @handler("DescribeStateMachineForExecution")
    def describe_state_machine_for_execution(
        self,
        context: RequestContext,
        execution_arn: Arn,
        included_data: IncludedData | None = None,
        **kwargs,
    ) -> DescribeStateMachineForExecutionOutput:
        raise NotImplementedError

    @handler("GetActivityTask")
    def get_activity_task(
        self, context: RequestContext, activity_arn: Arn, worker_name: Name | None = None, **kwargs
    ) -> GetActivityTaskOutput:
        raise NotImplementedError

    @handler("GetExecutionHistory")
    def get_execution_history(
        self,
        context: RequestContext,
        execution_arn: Arn,
        max_results: PageSize | None = None,
        reverse_order: ReverseOrder | None = None,
        next_token: PageToken | None = None,
        include_execution_data: IncludeExecutionDataGetExecutionHistory | None = None,
        **kwargs,
    ) -> GetExecutionHistoryOutput:
        raise NotImplementedError

    @handler("ListActivities")
    def list_activities(
        self,
        context: RequestContext,
        max_results: PageSize | None = None,
        next_token: PageToken | None = None,
        **kwargs,
    ) -> ListActivitiesOutput:
        raise NotImplementedError

    @handler("ListExecutions")
    def list_executions(
        self,
        context: RequestContext,
        state_machine_arn: Arn | None = None,
        status_filter: ExecutionStatus | None = None,
        max_results: PageSize | None = None,
        next_token: ListExecutionsPageToken | None = None,
        map_run_arn: LongArn | None = None,
        redrive_filter: ExecutionRedriveFilter | None = None,
        **kwargs,
    ) -> ListExecutionsOutput:
        raise NotImplementedError

    @handler("ListMapRuns")
    def list_map_runs(
        self,
        context: RequestContext,
        execution_arn: Arn,
        max_results: PageSize | None = None,
        next_token: PageToken | None = None,
        **kwargs,
    ) -> ListMapRunsOutput:
        raise NotImplementedError

    @handler("ListStateMachineAliases")
    def list_state_machine_aliases(
        self,
        context: RequestContext,
        state_machine_arn: Arn,
        next_token: PageToken | None = None,
        max_results: PageSize | None = None,
        **kwargs,
    ) -> ListStateMachineAliasesOutput:
        raise NotImplementedError

    @handler("ListStateMachineVersions")
    def list_state_machine_versions(
        self,
        context: RequestContext,
        state_machine_arn: Arn,
        next_token: PageToken | None = None,
        max_results: PageSize | None = None,
        **kwargs,
    ) -> ListStateMachineVersionsOutput:
        raise NotImplementedError

    @handler("ListStateMachines")
    def list_state_machines(
        self,
        context: RequestContext,
        max_results: PageSize | None = None,
        next_token: PageToken | None = None,
        **kwargs,
    ) -> ListStateMachinesOutput:
        raise NotImplementedError

    @handler("ListTagsForResource")
    def list_tags_for_resource(
        self, context: RequestContext, resource_arn: Arn, **kwargs
    ) -> ListTagsForResourceOutput:
        raise NotImplementedError

    @handler("PublishStateMachineVersion")
    def publish_state_machine_version(
        self,
        context: RequestContext,
        state_machine_arn: Arn,
        revision_id: RevisionId | None = None,
        description: VersionDescription | None = None,
        **kwargs,
    ) -> PublishStateMachineVersionOutput:
        raise NotImplementedError

    @handler("RedriveExecution")
    def redrive_execution(
        self,
        context: RequestContext,
        execution_arn: Arn,
        client_token: ClientToken | None = None,
        **kwargs,
    ) -> RedriveExecutionOutput:
        raise NotImplementedError

    @handler("SendTaskFailure")
    def send_task_failure(
        self,
        context: RequestContext,
        task_token: TaskToken,
        error: SensitiveError | None = None,
        cause: SensitiveCause | None = None,
        **kwargs,
    ) -> SendTaskFailureOutput:
        raise NotImplementedError

    @handler("SendTaskHeartbeat")
    def send_task_heartbeat(
        self, context: RequestContext, task_token: TaskToken, **kwargs
    ) -> SendTaskHeartbeatOutput:
        raise NotImplementedError

    @handler("SendTaskSuccess")
    def send_task_success(
        self, context: RequestContext, task_token: TaskToken, output: SensitiveData, **kwargs
    ) -> SendTaskSuccessOutput:
        raise NotImplementedError

    @handler("StartExecution")
    def start_execution(
        self,
        context: RequestContext,
        state_machine_arn: Arn,
        name: Name | None = None,
        input: SensitiveData | None = None,
        trace_header: TraceHeader | None = None,
        **kwargs,
    ) -> StartExecutionOutput:
        raise NotImplementedError

    @handler("StartSyncExecution")
    def start_sync_execution(
        self,
        context: RequestContext,
        state_machine_arn: Arn,
        name: Name | None = None,
        input: SensitiveData | None = None,
        trace_header: TraceHeader | None = None,
        included_data: IncludedData | None = None,
        **kwargs,
    ) -> StartSyncExecutionOutput:
        raise NotImplementedError

    @handler("StopExecution")
    def stop_execution(
        self,
        context: RequestContext,
        execution_arn: Arn,
        error: SensitiveError | None = None,
        cause: SensitiveCause | None = None,
        **kwargs,
    ) -> StopExecutionOutput:
        raise NotImplementedError

    @handler("TagResource")
    def tag_resource(
        self, context: RequestContext, resource_arn: Arn, tags: TagList, **kwargs
    ) -> TagResourceOutput:
        raise NotImplementedError

    @handler("TestState")
    def test_state(
        self,
        context: RequestContext,
        definition: Definition,
        role_arn: Arn | None = None,
        input: SensitiveData | None = None,
        inspection_level: InspectionLevel | None = None,
        reveal_secrets: RevealSecrets | None = None,
        variables: SensitiveData | None = None,
        **kwargs,
    ) -> TestStateOutput:
        raise NotImplementedError

    @handler("UntagResource")
    def untag_resource(
        self, context: RequestContext, resource_arn: Arn, tag_keys: TagKeyList, **kwargs
    ) -> UntagResourceOutput:
        raise NotImplementedError

    @handler("UpdateMapRun")
    def update_map_run(
        self,
        context: RequestContext,
        map_run_arn: LongArn,
        max_concurrency: MaxConcurrency | None = None,
        tolerated_failure_percentage: ToleratedFailurePercentage | None = None,
        tolerated_failure_count: ToleratedFailureCount | None = None,
        **kwargs,
    ) -> UpdateMapRunOutput:
        raise NotImplementedError

    @handler("UpdateStateMachine")
    def update_state_machine(
        self,
        context: RequestContext,
        state_machine_arn: Arn,
        definition: Definition | None = None,
        role_arn: Arn | None = None,
        logging_configuration: LoggingConfiguration | None = None,
        tracing_configuration: TracingConfiguration | None = None,
        publish: Publish | None = None,
        version_description: VersionDescription | None = None,
        encryption_configuration: EncryptionConfiguration | None = None,
        **kwargs,
    ) -> UpdateStateMachineOutput:
        raise NotImplementedError

    @handler("UpdateStateMachineAlias")
    def update_state_machine_alias(
        self,
        context: RequestContext,
        state_machine_alias_arn: Arn,
        description: AliasDescription | None = None,
        routing_configuration: RoutingConfigurationList | None = None,
        **kwargs,
    ) -> UpdateStateMachineAliasOutput:
        raise NotImplementedError

    @handler("ValidateStateMachineDefinition", expand=False)
    def validate_state_machine_definition(
        self, context: RequestContext, request: ValidateStateMachineDefinitionInput, **kwargs
    ) -> ValidateStateMachineDefinitionOutput:
        raise NotImplementedError
