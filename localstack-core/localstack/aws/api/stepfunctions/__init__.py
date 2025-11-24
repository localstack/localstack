from datetime import datetime
from enum import StrEnum
from typing import TypedDict

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
ExceptionHandlerIndex = int
HTTPBody = str
HTTPHeaders = str
HTTPMethod = str
HTTPProtocol = str
HTTPStatusCode = str
HTTPStatusMessage = str
Identity = str
IncludeExecutionData = bool
IncludeExecutionDataGetExecutionHistory = bool
InspectionMaxConcurrency = int
InspectionToleratedFailureCount = int
InspectionToleratedFailurePercentage = float
KmsDataKeyReusePeriodSeconds = int
KmsKeyId = str
ListExecutionsPageToken = str
LongArn = str
MapIterationFailureCount = int
MapRunLabel = str
MaxConcurrency = int
Name = str
PageSize = int
PageToken = str
Publish = bool
RedriveCount = int
RetrierRetryCount = int
RetryBackoffIntervalSeconds = int
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
TestStateStateName = str
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


class MockResponseValidationMode(StrEnum):
    STRICT = "STRICT"
    PRESENT = "PRESENT"
    NONE = "NONE"


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
    kmsKeyState: KmsKeyState | None


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
    resourceName: Arn | None


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
    resourceName: Arn | None


class ValidationException(ServiceException):
    code: str = "ValidationException"
    sender_fault: bool = False
    status_code: int = 400
    reason: ValidationExceptionReason | None


class ActivityFailedEventDetails(TypedDict, total=False):
    error: SensitiveError | None
    cause: SensitiveCause | None


Timestamp = datetime


class ActivityListItem(TypedDict, total=False):
    activityArn: Arn
    name: Name
    creationDate: Timestamp


ActivityList = list[ActivityListItem]


class ActivityScheduleFailedEventDetails(TypedDict, total=False):
    error: SensitiveError | None
    cause: SensitiveCause | None


TimeoutInSeconds = int


class HistoryEventExecutionDataDetails(TypedDict, total=False):
    truncated: truncated | None


class ActivityScheduledEventDetails(TypedDict, total=False):
    resource: Arn
    input: SensitiveData | None
    inputDetails: HistoryEventExecutionDataDetails | None
    timeoutInSeconds: TimeoutInSeconds | None
    heartbeatInSeconds: TimeoutInSeconds | None


class ActivityStartedEventDetails(TypedDict, total=False):
    workerName: Identity | None


class ActivitySucceededEventDetails(TypedDict, total=False):
    output: SensitiveData | None
    outputDetails: HistoryEventExecutionDataDetails | None


class ActivityTimedOutEventDetails(TypedDict, total=False):
    error: SensitiveError | None
    cause: SensitiveCause | None


AssignedVariables = dict[VariableName, VariableValue]


class AssignedVariablesDetails(TypedDict, total=False):
    truncated: truncated | None


BilledDuration = int
BilledMemoryUsed = int


class BillingDetails(TypedDict, total=False):
    billedMemoryUsedInMB: BilledMemoryUsed | None
    billedDurationInMilliseconds: BilledDuration | None


class CloudWatchEventsExecutionDataDetails(TypedDict, total=False):
    included: includedDetails | None


class CloudWatchLogsLogGroup(TypedDict, total=False):
    logGroupArn: Arn | None


class EncryptionConfiguration(TypedDict, total=False):
    kmsKeyId: KmsKeyId | None
    kmsDataKeyReusePeriodSeconds: KmsDataKeyReusePeriodSeconds | None
    type: EncryptionType


class Tag(TypedDict, total=False):
    key: TagKey | None
    value: TagValue | None


TagList = list[Tag]


class CreateActivityInput(ServiceRequest):
    name: Name
    tags: TagList | None
    encryptionConfiguration: EncryptionConfiguration | None


class CreateActivityOutput(TypedDict, total=False):
    activityArn: Arn
    creationDate: Timestamp


class RoutingConfigurationListItem(TypedDict, total=False):
    stateMachineVersionArn: Arn
    weight: VersionWeight


RoutingConfigurationList = list[RoutingConfigurationListItem]


class CreateStateMachineAliasInput(ServiceRequest):
    description: AliasDescription | None
    name: CharacterRestrictedName
    routingConfiguration: RoutingConfigurationList


class CreateStateMachineAliasOutput(TypedDict, total=False):
    stateMachineAliasArn: Arn
    creationDate: Timestamp


class TracingConfiguration(TypedDict, total=False):
    enabled: Enabled | None


class LogDestination(TypedDict, total=False):
    cloudWatchLogsLogGroup: CloudWatchLogsLogGroup | None


LogDestinationList = list[LogDestination]


class LoggingConfiguration(TypedDict, total=False):
    level: LogLevel | None
    includeExecutionData: IncludeExecutionData | None
    destinations: LogDestinationList | None


class CreateStateMachineInput(TypedDict, total=False):
    name: Name
    definition: Definition
    roleArn: Arn
    type: StateMachineType | None
    loggingConfiguration: LoggingConfiguration | None
    tags: TagList | None
    tracingConfiguration: TracingConfiguration | None
    publish: Publish | None
    versionDescription: VersionDescription | None
    encryptionConfiguration: EncryptionConfiguration | None


class CreateStateMachineOutput(TypedDict, total=False):
    stateMachineArn: Arn
    creationDate: Timestamp
    stateMachineVersionArn: Arn | None


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
    encryptionConfiguration: EncryptionConfiguration | None


class DescribeExecutionInput(ServiceRequest):
    executionArn: Arn
    includedData: IncludedData | None


class DescribeExecutionOutput(TypedDict, total=False):
    executionArn: Arn
    stateMachineArn: Arn
    name: Name | None
    status: ExecutionStatus
    startDate: Timestamp
    stopDate: Timestamp | None
    input: SensitiveData | None
    inputDetails: CloudWatchEventsExecutionDataDetails | None
    output: SensitiveData | None
    outputDetails: CloudWatchEventsExecutionDataDetails | None
    traceHeader: TraceHeader | None
    mapRunArn: LongArn | None
    error: SensitiveError | None
    cause: SensitiveCause | None
    stateMachineVersionArn: Arn | None
    stateMachineAliasArn: Arn | None
    redriveCount: RedriveCount | None
    redriveDate: Timestamp | None
    redriveStatus: ExecutionRedriveStatus | None
    redriveStatusReason: SensitiveData | None


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
    failuresNotRedrivable: LongObject | None
    pendingRedrive: LongObject | None


class MapRunItemCounts(TypedDict, total=False):
    pending: UnsignedLong
    running: UnsignedLong
    succeeded: UnsignedLong
    failed: UnsignedLong
    timedOut: UnsignedLong
    aborted: UnsignedLong
    total: UnsignedLong
    resultsWritten: UnsignedLong
    failuresNotRedrivable: LongObject | None
    pendingRedrive: LongObject | None


ToleratedFailureCount = int


class DescribeMapRunOutput(TypedDict, total=False):
    mapRunArn: LongArn
    executionArn: Arn
    status: MapRunStatus
    startDate: Timestamp
    stopDate: Timestamp | None
    maxConcurrency: MaxConcurrency
    toleratedFailurePercentage: ToleratedFailurePercentage
    toleratedFailureCount: ToleratedFailureCount
    itemCounts: MapRunItemCounts
    executionCounts: MapRunExecutionCounts
    redriveCount: RedriveCount | None
    redriveDate: Timestamp | None


class DescribeStateMachineAliasInput(ServiceRequest):
    stateMachineAliasArn: Arn


class DescribeStateMachineAliasOutput(TypedDict, total=False):
    stateMachineAliasArn: Arn | None
    name: Name | None
    description: AliasDescription | None
    routingConfiguration: RoutingConfigurationList | None
    creationDate: Timestamp | None
    updateDate: Timestamp | None


class DescribeStateMachineForExecutionInput(ServiceRequest):
    executionArn: Arn
    includedData: IncludedData | None


VariableNameList = list[VariableName]
VariableReferences = dict[StateName, VariableNameList]


class DescribeStateMachineForExecutionOutput(TypedDict, total=False):
    stateMachineArn: Arn
    name: Name
    definition: Definition
    roleArn: Arn
    updateDate: Timestamp
    loggingConfiguration: LoggingConfiguration | None
    tracingConfiguration: TracingConfiguration | None
    mapRunArn: LongArn | None
    label: MapRunLabel | None
    revisionId: RevisionId | None
    encryptionConfiguration: EncryptionConfiguration | None
    variableReferences: VariableReferences | None


class DescribeStateMachineInput(ServiceRequest):
    stateMachineArn: Arn
    includedData: IncludedData | None


class DescribeStateMachineOutput(TypedDict, total=False):
    stateMachineArn: Arn
    name: Name
    status: StateMachineStatus | None
    definition: Definition
    roleArn: Arn
    type: StateMachineType
    creationDate: Timestamp
    loggingConfiguration: LoggingConfiguration | None
    tracingConfiguration: TracingConfiguration | None
    label: MapRunLabel | None
    revisionId: RevisionId | None
    description: VersionDescription | None
    encryptionConfiguration: EncryptionConfiguration | None
    variableReferences: VariableReferences | None


class EvaluationFailedEventDetails(TypedDict, total=False):
    error: SensitiveError | None
    cause: SensitiveCause | None
    location: EvaluationFailureLocation | None
    state: StateName


EventId = int


class ExecutionAbortedEventDetails(TypedDict, total=False):
    error: SensitiveError | None
    cause: SensitiveCause | None


class ExecutionFailedEventDetails(TypedDict, total=False):
    error: SensitiveError | None
    cause: SensitiveCause | None


class ExecutionListItem(TypedDict, total=False):
    executionArn: Arn
    stateMachineArn: Arn
    name: Name
    status: ExecutionStatus
    startDate: Timestamp
    stopDate: Timestamp | None
    mapRunArn: LongArn | None
    itemCount: UnsignedInteger | None
    stateMachineVersionArn: Arn | None
    stateMachineAliasArn: Arn | None
    redriveCount: RedriveCount | None
    redriveDate: Timestamp | None


ExecutionList = list[ExecutionListItem]


class ExecutionRedrivenEventDetails(TypedDict, total=False):
    redriveCount: RedriveCount | None


class ExecutionStartedEventDetails(TypedDict, total=False):
    input: SensitiveData | None
    inputDetails: HistoryEventExecutionDataDetails | None
    roleArn: Arn | None
    stateMachineAliasArn: Arn | None
    stateMachineVersionArn: Arn | None


class ExecutionSucceededEventDetails(TypedDict, total=False):
    output: SensitiveData | None
    outputDetails: HistoryEventExecutionDataDetails | None


class ExecutionTimedOutEventDetails(TypedDict, total=False):
    error: SensitiveError | None
    cause: SensitiveCause | None


class GetActivityTaskInput(ServiceRequest):
    activityArn: Arn
    workerName: Name | None


class GetActivityTaskOutput(TypedDict, total=False):
    taskToken: TaskToken | None
    input: SensitiveDataJobInput | None


class GetExecutionHistoryInput(ServiceRequest):
    executionArn: Arn
    maxResults: PageSize | None
    reverseOrder: ReverseOrder | None
    nextToken: PageToken | None
    includeExecutionData: IncludeExecutionDataGetExecutionHistory | None


class MapRunRedrivenEventDetails(TypedDict, total=False):
    mapRunArn: LongArn | None
    redriveCount: RedriveCount | None


class MapRunFailedEventDetails(TypedDict, total=False):
    error: SensitiveError | None
    cause: SensitiveCause | None


class MapRunStartedEventDetails(TypedDict, total=False):
    mapRunArn: LongArn | None


class StateExitedEventDetails(TypedDict, total=False):
    name: Name
    output: SensitiveData | None
    outputDetails: HistoryEventExecutionDataDetails | None
    assignedVariables: AssignedVariables | None
    assignedVariablesDetails: AssignedVariablesDetails | None


class StateEnteredEventDetails(TypedDict, total=False):
    name: Name
    input: SensitiveData | None
    inputDetails: HistoryEventExecutionDataDetails | None


class LambdaFunctionTimedOutEventDetails(TypedDict, total=False):
    error: SensitiveError | None
    cause: SensitiveCause | None


class LambdaFunctionSucceededEventDetails(TypedDict, total=False):
    output: SensitiveData | None
    outputDetails: HistoryEventExecutionDataDetails | None


class LambdaFunctionStartFailedEventDetails(TypedDict, total=False):
    error: SensitiveError | None
    cause: SensitiveCause | None


class TaskCredentials(TypedDict, total=False):
    roleArn: LongArn | None


class LambdaFunctionScheduledEventDetails(TypedDict, total=False):
    resource: Arn
    input: SensitiveData | None
    inputDetails: HistoryEventExecutionDataDetails | None
    timeoutInSeconds: TimeoutInSeconds | None
    taskCredentials: TaskCredentials | None


class LambdaFunctionScheduleFailedEventDetails(TypedDict, total=False):
    error: SensitiveError | None
    cause: SensitiveCause | None


class LambdaFunctionFailedEventDetails(TypedDict, total=False):
    error: SensitiveError | None
    cause: SensitiveCause | None


class MapIterationEventDetails(TypedDict, total=False):
    name: Name | None
    index: UnsignedInteger | None


class MapStateStartedEventDetails(TypedDict, total=False):
    length: UnsignedInteger | None


class TaskTimedOutEventDetails(TypedDict, total=False):
    resourceType: Name
    resource: Name
    error: SensitiveError | None
    cause: SensitiveCause | None


class TaskSucceededEventDetails(TypedDict, total=False):
    resourceType: Name
    resource: Name
    output: SensitiveData | None
    outputDetails: HistoryEventExecutionDataDetails | None


class TaskSubmittedEventDetails(TypedDict, total=False):
    resourceType: Name
    resource: Name
    output: SensitiveData | None
    outputDetails: HistoryEventExecutionDataDetails | None


class TaskSubmitFailedEventDetails(TypedDict, total=False):
    resourceType: Name
    resource: Name
    error: SensitiveError | None
    cause: SensitiveCause | None


class TaskStartedEventDetails(TypedDict, total=False):
    resourceType: Name
    resource: Name


class TaskStartFailedEventDetails(TypedDict, total=False):
    resourceType: Name
    resource: Name
    error: SensitiveError | None
    cause: SensitiveCause | None


class TaskScheduledEventDetails(TypedDict, total=False):
    resourceType: Name
    resource: Name
    region: Name
    parameters: ConnectorParameters
    timeoutInSeconds: TimeoutInSeconds | None
    heartbeatInSeconds: TimeoutInSeconds | None
    taskCredentials: TaskCredentials | None


class TaskFailedEventDetails(TypedDict, total=False):
    resourceType: Name
    resource: Name
    error: SensitiveError | None
    cause: SensitiveCause | None


class HistoryEvent(TypedDict, total=False):
    timestamp: Timestamp
    type: HistoryEventType
    id: EventId
    previousEventId: EventId | None
    activityFailedEventDetails: ActivityFailedEventDetails | None
    activityScheduleFailedEventDetails: ActivityScheduleFailedEventDetails | None
    activityScheduledEventDetails: ActivityScheduledEventDetails | None
    activityStartedEventDetails: ActivityStartedEventDetails | None
    activitySucceededEventDetails: ActivitySucceededEventDetails | None
    activityTimedOutEventDetails: ActivityTimedOutEventDetails | None
    taskFailedEventDetails: TaskFailedEventDetails | None
    taskScheduledEventDetails: TaskScheduledEventDetails | None
    taskStartFailedEventDetails: TaskStartFailedEventDetails | None
    taskStartedEventDetails: TaskStartedEventDetails | None
    taskSubmitFailedEventDetails: TaskSubmitFailedEventDetails | None
    taskSubmittedEventDetails: TaskSubmittedEventDetails | None
    taskSucceededEventDetails: TaskSucceededEventDetails | None
    taskTimedOutEventDetails: TaskTimedOutEventDetails | None
    executionFailedEventDetails: ExecutionFailedEventDetails | None
    executionStartedEventDetails: ExecutionStartedEventDetails | None
    executionSucceededEventDetails: ExecutionSucceededEventDetails | None
    executionAbortedEventDetails: ExecutionAbortedEventDetails | None
    executionTimedOutEventDetails: ExecutionTimedOutEventDetails | None
    executionRedrivenEventDetails: ExecutionRedrivenEventDetails | None
    mapStateStartedEventDetails: MapStateStartedEventDetails | None
    mapIterationStartedEventDetails: MapIterationEventDetails | None
    mapIterationSucceededEventDetails: MapIterationEventDetails | None
    mapIterationFailedEventDetails: MapIterationEventDetails | None
    mapIterationAbortedEventDetails: MapIterationEventDetails | None
    lambdaFunctionFailedEventDetails: LambdaFunctionFailedEventDetails | None
    lambdaFunctionScheduleFailedEventDetails: LambdaFunctionScheduleFailedEventDetails | None
    lambdaFunctionScheduledEventDetails: LambdaFunctionScheduledEventDetails | None
    lambdaFunctionStartFailedEventDetails: LambdaFunctionStartFailedEventDetails | None
    lambdaFunctionSucceededEventDetails: LambdaFunctionSucceededEventDetails | None
    lambdaFunctionTimedOutEventDetails: LambdaFunctionTimedOutEventDetails | None
    stateEnteredEventDetails: StateEnteredEventDetails | None
    stateExitedEventDetails: StateExitedEventDetails | None
    mapRunStartedEventDetails: MapRunStartedEventDetails | None
    mapRunFailedEventDetails: MapRunFailedEventDetails | None
    mapRunRedrivenEventDetails: MapRunRedrivenEventDetails | None
    evaluationFailedEventDetails: EvaluationFailedEventDetails | None


HistoryEventList = list[HistoryEvent]


class GetExecutionHistoryOutput(TypedDict, total=False):
    events: HistoryEventList
    nextToken: PageToken | None


class InspectionErrorDetails(TypedDict, total=False):
    catchIndex: ExceptionHandlerIndex | None
    retryIndex: ExceptionHandlerIndex | None
    retryBackoffIntervalSeconds: RetryBackoffIntervalSeconds | None


class InspectionDataResponse(TypedDict, total=False):
    protocol: HTTPProtocol | None
    statusCode: HTTPStatusCode | None
    statusMessage: HTTPStatusMessage | None
    headers: HTTPHeaders | None
    body: HTTPBody | None


class InspectionDataRequest(TypedDict, total=False):
    protocol: HTTPProtocol | None
    method: HTTPMethod | None
    url: URL | None
    headers: HTTPHeaders | None
    body: HTTPBody | None


class InspectionData(TypedDict, total=False):
    input: SensitiveData | None
    afterArguments: SensitiveData | None
    afterInputPath: SensitiveData | None
    afterParameters: SensitiveData | None
    result: SensitiveData | None
    afterResultSelector: SensitiveData | None
    afterResultPath: SensitiveData | None
    request: InspectionDataRequest | None
    response: InspectionDataResponse | None
    variables: SensitiveData | None
    errorDetails: InspectionErrorDetails | None
    afterItemsPath: SensitiveData | None
    afterItemSelector: SensitiveData | None
    afterItemBatcher: SensitiveData | None
    afterItemsPointer: SensitiveData | None
    toleratedFailureCount: InspectionToleratedFailureCount | None
    toleratedFailurePercentage: InspectionToleratedFailurePercentage | None
    maxConcurrency: InspectionMaxConcurrency | None


class ListActivitiesInput(ServiceRequest):
    maxResults: PageSize | None
    nextToken: PageToken | None


class ListActivitiesOutput(TypedDict, total=False):
    activities: ActivityList
    nextToken: PageToken | None


class ListExecutionsInput(ServiceRequest):
    stateMachineArn: Arn | None
    statusFilter: ExecutionStatus | None
    maxResults: PageSize | None
    nextToken: ListExecutionsPageToken | None
    mapRunArn: LongArn | None
    redriveFilter: ExecutionRedriveFilter | None


class ListExecutionsOutput(TypedDict, total=False):
    executions: ExecutionList
    nextToken: ListExecutionsPageToken | None


class ListMapRunsInput(ServiceRequest):
    executionArn: Arn
    maxResults: PageSize | None
    nextToken: PageToken | None


class MapRunListItem(TypedDict, total=False):
    executionArn: Arn
    mapRunArn: LongArn
    stateMachineArn: Arn
    startDate: Timestamp
    stopDate: Timestamp | None


MapRunList = list[MapRunListItem]


class ListMapRunsOutput(TypedDict, total=False):
    mapRuns: MapRunList
    nextToken: PageToken | None


class ListStateMachineAliasesInput(ServiceRequest):
    stateMachineArn: Arn
    nextToken: PageToken | None
    maxResults: PageSize | None


class StateMachineAliasListItem(TypedDict, total=False):
    stateMachineAliasArn: LongArn
    creationDate: Timestamp


StateMachineAliasList = list[StateMachineAliasListItem]


class ListStateMachineAliasesOutput(TypedDict, total=False):
    stateMachineAliases: StateMachineAliasList
    nextToken: PageToken | None


class ListStateMachineVersionsInput(ServiceRequest):
    stateMachineArn: Arn
    nextToken: PageToken | None
    maxResults: PageSize | None


class StateMachineVersionListItem(TypedDict, total=False):
    stateMachineVersionArn: LongArn
    creationDate: Timestamp


StateMachineVersionList = list[StateMachineVersionListItem]


class ListStateMachineVersionsOutput(TypedDict, total=False):
    stateMachineVersions: StateMachineVersionList
    nextToken: PageToken | None


class ListStateMachinesInput(ServiceRequest):
    maxResults: PageSize | None
    nextToken: PageToken | None


class StateMachineListItem(TypedDict, total=False):
    stateMachineArn: Arn
    name: Name
    type: StateMachineType
    creationDate: Timestamp


StateMachineList = list[StateMachineListItem]


class ListStateMachinesOutput(TypedDict, total=False):
    stateMachines: StateMachineList
    nextToken: PageToken | None


class ListTagsForResourceInput(ServiceRequest):
    resourceArn: Arn


class ListTagsForResourceOutput(TypedDict, total=False):
    tags: TagList | None


class MockErrorOutput(TypedDict, total=False):
    error: SensitiveError | None
    cause: SensitiveCause | None


class MockInput(TypedDict, total=False):
    result: SensitiveData | None
    errorOutput: MockErrorOutput | None
    fieldValidationMode: MockResponseValidationMode | None


class PublishStateMachineVersionInput(ServiceRequest):
    stateMachineArn: Arn
    revisionId: RevisionId | None
    description: VersionDescription | None


class PublishStateMachineVersionOutput(TypedDict, total=False):
    creationDate: Timestamp
    stateMachineVersionArn: Arn


class RedriveExecutionInput(ServiceRequest):
    executionArn: Arn
    clientToken: ClientToken | None


class RedriveExecutionOutput(TypedDict, total=False):
    redriveDate: Timestamp


class SendTaskFailureInput(ServiceRequest):
    taskToken: TaskToken
    error: SensitiveError | None
    cause: SensitiveCause | None


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
    name: Name | None
    input: SensitiveData | None
    traceHeader: TraceHeader | None


class StartExecutionOutput(TypedDict, total=False):
    executionArn: Arn
    startDate: Timestamp


class StartSyncExecutionInput(ServiceRequest):
    stateMachineArn: Arn
    name: Name | None
    input: SensitiveData | None
    traceHeader: TraceHeader | None
    includedData: IncludedData | None


class StartSyncExecutionOutput(TypedDict, total=False):
    executionArn: Arn
    stateMachineArn: Arn | None
    name: Name | None
    startDate: Timestamp
    stopDate: Timestamp
    status: SyncExecutionStatus
    error: SensitiveError | None
    cause: SensitiveCause | None
    input: SensitiveData | None
    inputDetails: CloudWatchEventsExecutionDataDetails | None
    output: SensitiveData | None
    outputDetails: CloudWatchEventsExecutionDataDetails | None
    traceHeader: TraceHeader | None
    billingDetails: BillingDetails | None


class StopExecutionInput(ServiceRequest):
    executionArn: Arn
    error: SensitiveError | None
    cause: SensitiveCause | None


class StopExecutionOutput(TypedDict, total=False):
    stopDate: Timestamp


TagKeyList = list[TagKey]


class TagResourceInput(ServiceRequest):
    resourceArn: Arn
    tags: TagList


class TagResourceOutput(TypedDict, total=False):
    pass


class TestStateConfiguration(TypedDict, total=False):
    retrierRetryCount: RetrierRetryCount | None
    errorCausedByState: TestStateStateName | None
    mapIterationFailureCount: MapIterationFailureCount | None
    mapItemReaderData: SensitiveData | None


class TestStateInput(ServiceRequest):
    definition: Definition
    roleArn: Arn | None
    input: SensitiveData | None
    inspectionLevel: InspectionLevel | None
    revealSecrets: RevealSecrets | None
    variables: SensitiveData | None
    stateName: TestStateStateName | None
    mock: MockInput | None
    context: SensitiveData | None
    stateConfiguration: TestStateConfiguration | None


class TestStateOutput(TypedDict, total=False):
    output: SensitiveData | None
    error: SensitiveError | None
    cause: SensitiveCause | None
    inspectionData: InspectionData | None
    nextState: StateName | None
    status: TestExecutionStatus | None


class UntagResourceInput(ServiceRequest):
    resourceArn: Arn
    tagKeys: TagKeyList


class UntagResourceOutput(TypedDict, total=False):
    pass


class UpdateMapRunInput(ServiceRequest):
    mapRunArn: LongArn
    maxConcurrency: MaxConcurrency | None
    toleratedFailurePercentage: ToleratedFailurePercentage | None
    toleratedFailureCount: ToleratedFailureCount | None


class UpdateMapRunOutput(TypedDict, total=False):
    pass


class UpdateStateMachineAliasInput(ServiceRequest):
    stateMachineAliasArn: Arn
    description: AliasDescription | None
    routingConfiguration: RoutingConfigurationList | None


class UpdateStateMachineAliasOutput(TypedDict, total=False):
    updateDate: Timestamp


class UpdateStateMachineInput(ServiceRequest):
    stateMachineArn: Arn
    definition: Definition | None
    roleArn: Arn | None
    loggingConfiguration: LoggingConfiguration | None
    tracingConfiguration: TracingConfiguration | None
    publish: Publish | None
    versionDescription: VersionDescription | None
    encryptionConfiguration: EncryptionConfiguration | None


class UpdateStateMachineOutput(TypedDict, total=False):
    updateDate: Timestamp
    revisionId: RevisionId | None
    stateMachineVersionArn: Arn | None


class ValidateStateMachineDefinitionDiagnostic(TypedDict, total=False):
    severity: ValidateStateMachineDefinitionSeverity
    code: ValidateStateMachineDefinitionCode
    message: ValidateStateMachineDefinitionMessage
    location: ValidateStateMachineDefinitionLocation | None


ValidateStateMachineDefinitionDiagnosticList = list[ValidateStateMachineDefinitionDiagnostic]


class ValidateStateMachineDefinitionInput(TypedDict, total=False):
    definition: Definition
    type: StateMachineType | None
    severity: ValidateStateMachineDefinitionSeverity | None
    maxResults: ValidateStateMachineDefinitionMaxResult | None


class ValidateStateMachineDefinitionOutput(TypedDict, total=False):
    result: ValidateStateMachineDefinitionResultCode
    diagnostics: ValidateStateMachineDefinitionDiagnosticList
    truncated: ValidateStateMachineDefinitionTruncated | None


class StepfunctionsApi:
    service: str = "stepfunctions"
    version: str = "2016-11-23"

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

    @handler("TestState", expand=False)
    def test_state(
        self, context: RequestContext, request: TestStateInput, **kwargs
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
