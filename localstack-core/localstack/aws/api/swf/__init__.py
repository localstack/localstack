from datetime import datetime
from enum import StrEnum
from typing import TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

ActivityId = str
Arn = str
Canceled = bool
CauseMessage = str
Count = int
Data = str
Description = str
DomainName = str
DurationInDays = str
DurationInSeconds = str
DurationInSecondsOptional = str
ErrorMessage = str
FailureReason = str
FunctionId = str
FunctionInput = str
FunctionName = str
Identity = str
LimitedData = str
MarkerName = str
Name = str
OpenDecisionTasksCount = int
PageSize = int
PageToken = str
ResourceTagKey = str
ResourceTagValue = str
ReverseOrder = bool
SignalName = str
StartAtPreviousStartedEvent = bool
Tag = str
TaskPriority = str
TaskToken = str
TerminateReason = str
TimerId = str
Truncated = bool
Version = str
VersionOptional = str
WorkflowId = str
WorkflowRunId = str
WorkflowRunIdOptional = str


class ActivityTaskTimeoutType(StrEnum):
    START_TO_CLOSE = "START_TO_CLOSE"
    SCHEDULE_TO_START = "SCHEDULE_TO_START"
    SCHEDULE_TO_CLOSE = "SCHEDULE_TO_CLOSE"
    HEARTBEAT = "HEARTBEAT"


class CancelTimerFailedCause(StrEnum):
    TIMER_ID_UNKNOWN = "TIMER_ID_UNKNOWN"
    OPERATION_NOT_PERMITTED = "OPERATION_NOT_PERMITTED"


class CancelWorkflowExecutionFailedCause(StrEnum):
    UNHANDLED_DECISION = "UNHANDLED_DECISION"
    OPERATION_NOT_PERMITTED = "OPERATION_NOT_PERMITTED"


class ChildPolicy(StrEnum):
    TERMINATE = "TERMINATE"
    REQUEST_CANCEL = "REQUEST_CANCEL"
    ABANDON = "ABANDON"


class CloseStatus(StrEnum):
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELED = "CANCELED"
    TERMINATED = "TERMINATED"
    CONTINUED_AS_NEW = "CONTINUED_AS_NEW"
    TIMED_OUT = "TIMED_OUT"


class CompleteWorkflowExecutionFailedCause(StrEnum):
    UNHANDLED_DECISION = "UNHANDLED_DECISION"
    OPERATION_NOT_PERMITTED = "OPERATION_NOT_PERMITTED"


class ContinueAsNewWorkflowExecutionFailedCause(StrEnum):
    UNHANDLED_DECISION = "UNHANDLED_DECISION"
    WORKFLOW_TYPE_DEPRECATED = "WORKFLOW_TYPE_DEPRECATED"
    WORKFLOW_TYPE_DOES_NOT_EXIST = "WORKFLOW_TYPE_DOES_NOT_EXIST"
    DEFAULT_EXECUTION_START_TO_CLOSE_TIMEOUT_UNDEFINED = (
        "DEFAULT_EXECUTION_START_TO_CLOSE_TIMEOUT_UNDEFINED"
    )
    DEFAULT_TASK_START_TO_CLOSE_TIMEOUT_UNDEFINED = "DEFAULT_TASK_START_TO_CLOSE_TIMEOUT_UNDEFINED"
    DEFAULT_TASK_LIST_UNDEFINED = "DEFAULT_TASK_LIST_UNDEFINED"
    DEFAULT_CHILD_POLICY_UNDEFINED = "DEFAULT_CHILD_POLICY_UNDEFINED"
    CONTINUE_AS_NEW_WORKFLOW_EXECUTION_RATE_EXCEEDED = (
        "CONTINUE_AS_NEW_WORKFLOW_EXECUTION_RATE_EXCEEDED"
    )
    OPERATION_NOT_PERMITTED = "OPERATION_NOT_PERMITTED"


class DecisionTaskTimeoutType(StrEnum):
    START_TO_CLOSE = "START_TO_CLOSE"
    SCHEDULE_TO_START = "SCHEDULE_TO_START"


class DecisionType(StrEnum):
    ScheduleActivityTask = "ScheduleActivityTask"
    RequestCancelActivityTask = "RequestCancelActivityTask"
    CompleteWorkflowExecution = "CompleteWorkflowExecution"
    FailWorkflowExecution = "FailWorkflowExecution"
    CancelWorkflowExecution = "CancelWorkflowExecution"
    ContinueAsNewWorkflowExecution = "ContinueAsNewWorkflowExecution"
    RecordMarker = "RecordMarker"
    StartTimer = "StartTimer"
    CancelTimer = "CancelTimer"
    SignalExternalWorkflowExecution = "SignalExternalWorkflowExecution"
    RequestCancelExternalWorkflowExecution = "RequestCancelExternalWorkflowExecution"
    StartChildWorkflowExecution = "StartChildWorkflowExecution"
    ScheduleLambdaFunction = "ScheduleLambdaFunction"


class EventType(StrEnum):
    WorkflowExecutionStarted = "WorkflowExecutionStarted"
    WorkflowExecutionCancelRequested = "WorkflowExecutionCancelRequested"
    WorkflowExecutionCompleted = "WorkflowExecutionCompleted"
    CompleteWorkflowExecutionFailed = "CompleteWorkflowExecutionFailed"
    WorkflowExecutionFailed = "WorkflowExecutionFailed"
    FailWorkflowExecutionFailed = "FailWorkflowExecutionFailed"
    WorkflowExecutionTimedOut = "WorkflowExecutionTimedOut"
    WorkflowExecutionCanceled = "WorkflowExecutionCanceled"
    CancelWorkflowExecutionFailed = "CancelWorkflowExecutionFailed"
    WorkflowExecutionContinuedAsNew = "WorkflowExecutionContinuedAsNew"
    ContinueAsNewWorkflowExecutionFailed = "ContinueAsNewWorkflowExecutionFailed"
    WorkflowExecutionTerminated = "WorkflowExecutionTerminated"
    DecisionTaskScheduled = "DecisionTaskScheduled"
    DecisionTaskStarted = "DecisionTaskStarted"
    DecisionTaskCompleted = "DecisionTaskCompleted"
    DecisionTaskTimedOut = "DecisionTaskTimedOut"
    ActivityTaskScheduled = "ActivityTaskScheduled"
    ScheduleActivityTaskFailed = "ScheduleActivityTaskFailed"
    ActivityTaskStarted = "ActivityTaskStarted"
    ActivityTaskCompleted = "ActivityTaskCompleted"
    ActivityTaskFailed = "ActivityTaskFailed"
    ActivityTaskTimedOut = "ActivityTaskTimedOut"
    ActivityTaskCanceled = "ActivityTaskCanceled"
    ActivityTaskCancelRequested = "ActivityTaskCancelRequested"
    RequestCancelActivityTaskFailed = "RequestCancelActivityTaskFailed"
    WorkflowExecutionSignaled = "WorkflowExecutionSignaled"
    MarkerRecorded = "MarkerRecorded"
    RecordMarkerFailed = "RecordMarkerFailed"
    TimerStarted = "TimerStarted"
    StartTimerFailed = "StartTimerFailed"
    TimerFired = "TimerFired"
    TimerCanceled = "TimerCanceled"
    CancelTimerFailed = "CancelTimerFailed"
    StartChildWorkflowExecutionInitiated = "StartChildWorkflowExecutionInitiated"
    StartChildWorkflowExecutionFailed = "StartChildWorkflowExecutionFailed"
    ChildWorkflowExecutionStarted = "ChildWorkflowExecutionStarted"
    ChildWorkflowExecutionCompleted = "ChildWorkflowExecutionCompleted"
    ChildWorkflowExecutionFailed = "ChildWorkflowExecutionFailed"
    ChildWorkflowExecutionTimedOut = "ChildWorkflowExecutionTimedOut"
    ChildWorkflowExecutionCanceled = "ChildWorkflowExecutionCanceled"
    ChildWorkflowExecutionTerminated = "ChildWorkflowExecutionTerminated"
    SignalExternalWorkflowExecutionInitiated = "SignalExternalWorkflowExecutionInitiated"
    SignalExternalWorkflowExecutionFailed = "SignalExternalWorkflowExecutionFailed"
    ExternalWorkflowExecutionSignaled = "ExternalWorkflowExecutionSignaled"
    RequestCancelExternalWorkflowExecutionInitiated = (
        "RequestCancelExternalWorkflowExecutionInitiated"
    )
    RequestCancelExternalWorkflowExecutionFailed = "RequestCancelExternalWorkflowExecutionFailed"
    ExternalWorkflowExecutionCancelRequested = "ExternalWorkflowExecutionCancelRequested"
    LambdaFunctionScheduled = "LambdaFunctionScheduled"
    LambdaFunctionStarted = "LambdaFunctionStarted"
    LambdaFunctionCompleted = "LambdaFunctionCompleted"
    LambdaFunctionFailed = "LambdaFunctionFailed"
    LambdaFunctionTimedOut = "LambdaFunctionTimedOut"
    ScheduleLambdaFunctionFailed = "ScheduleLambdaFunctionFailed"
    StartLambdaFunctionFailed = "StartLambdaFunctionFailed"


class ExecutionStatus(StrEnum):
    OPEN = "OPEN"
    CLOSED = "CLOSED"


class FailWorkflowExecutionFailedCause(StrEnum):
    UNHANDLED_DECISION = "UNHANDLED_DECISION"
    OPERATION_NOT_PERMITTED = "OPERATION_NOT_PERMITTED"


class LambdaFunctionTimeoutType(StrEnum):
    START_TO_CLOSE = "START_TO_CLOSE"


class RecordMarkerFailedCause(StrEnum):
    OPERATION_NOT_PERMITTED = "OPERATION_NOT_PERMITTED"


class RegistrationStatus(StrEnum):
    REGISTERED = "REGISTERED"
    DEPRECATED = "DEPRECATED"


class RequestCancelActivityTaskFailedCause(StrEnum):
    ACTIVITY_ID_UNKNOWN = "ACTIVITY_ID_UNKNOWN"
    OPERATION_NOT_PERMITTED = "OPERATION_NOT_PERMITTED"


class RequestCancelExternalWorkflowExecutionFailedCause(StrEnum):
    UNKNOWN_EXTERNAL_WORKFLOW_EXECUTION = "UNKNOWN_EXTERNAL_WORKFLOW_EXECUTION"
    REQUEST_CANCEL_EXTERNAL_WORKFLOW_EXECUTION_RATE_EXCEEDED = (
        "REQUEST_CANCEL_EXTERNAL_WORKFLOW_EXECUTION_RATE_EXCEEDED"
    )
    OPERATION_NOT_PERMITTED = "OPERATION_NOT_PERMITTED"


class ScheduleActivityTaskFailedCause(StrEnum):
    ACTIVITY_TYPE_DEPRECATED = "ACTIVITY_TYPE_DEPRECATED"
    ACTIVITY_TYPE_DOES_NOT_EXIST = "ACTIVITY_TYPE_DOES_NOT_EXIST"
    ACTIVITY_ID_ALREADY_IN_USE = "ACTIVITY_ID_ALREADY_IN_USE"
    OPEN_ACTIVITIES_LIMIT_EXCEEDED = "OPEN_ACTIVITIES_LIMIT_EXCEEDED"
    ACTIVITY_CREATION_RATE_EXCEEDED = "ACTIVITY_CREATION_RATE_EXCEEDED"
    DEFAULT_SCHEDULE_TO_CLOSE_TIMEOUT_UNDEFINED = "DEFAULT_SCHEDULE_TO_CLOSE_TIMEOUT_UNDEFINED"
    DEFAULT_TASK_LIST_UNDEFINED = "DEFAULT_TASK_LIST_UNDEFINED"
    DEFAULT_SCHEDULE_TO_START_TIMEOUT_UNDEFINED = "DEFAULT_SCHEDULE_TO_START_TIMEOUT_UNDEFINED"
    DEFAULT_START_TO_CLOSE_TIMEOUT_UNDEFINED = "DEFAULT_START_TO_CLOSE_TIMEOUT_UNDEFINED"
    DEFAULT_HEARTBEAT_TIMEOUT_UNDEFINED = "DEFAULT_HEARTBEAT_TIMEOUT_UNDEFINED"
    OPERATION_NOT_PERMITTED = "OPERATION_NOT_PERMITTED"


class ScheduleLambdaFunctionFailedCause(StrEnum):
    ID_ALREADY_IN_USE = "ID_ALREADY_IN_USE"
    OPEN_LAMBDA_FUNCTIONS_LIMIT_EXCEEDED = "OPEN_LAMBDA_FUNCTIONS_LIMIT_EXCEEDED"
    LAMBDA_FUNCTION_CREATION_RATE_EXCEEDED = "LAMBDA_FUNCTION_CREATION_RATE_EXCEEDED"
    LAMBDA_SERVICE_NOT_AVAILABLE_IN_REGION = "LAMBDA_SERVICE_NOT_AVAILABLE_IN_REGION"


class SignalExternalWorkflowExecutionFailedCause(StrEnum):
    UNKNOWN_EXTERNAL_WORKFLOW_EXECUTION = "UNKNOWN_EXTERNAL_WORKFLOW_EXECUTION"
    SIGNAL_EXTERNAL_WORKFLOW_EXECUTION_RATE_EXCEEDED = (
        "SIGNAL_EXTERNAL_WORKFLOW_EXECUTION_RATE_EXCEEDED"
    )
    OPERATION_NOT_PERMITTED = "OPERATION_NOT_PERMITTED"


class StartChildWorkflowExecutionFailedCause(StrEnum):
    WORKFLOW_TYPE_DOES_NOT_EXIST = "WORKFLOW_TYPE_DOES_NOT_EXIST"
    WORKFLOW_TYPE_DEPRECATED = "WORKFLOW_TYPE_DEPRECATED"
    OPEN_CHILDREN_LIMIT_EXCEEDED = "OPEN_CHILDREN_LIMIT_EXCEEDED"
    OPEN_WORKFLOWS_LIMIT_EXCEEDED = "OPEN_WORKFLOWS_LIMIT_EXCEEDED"
    CHILD_CREATION_RATE_EXCEEDED = "CHILD_CREATION_RATE_EXCEEDED"
    WORKFLOW_ALREADY_RUNNING = "WORKFLOW_ALREADY_RUNNING"
    DEFAULT_EXECUTION_START_TO_CLOSE_TIMEOUT_UNDEFINED = (
        "DEFAULT_EXECUTION_START_TO_CLOSE_TIMEOUT_UNDEFINED"
    )
    DEFAULT_TASK_LIST_UNDEFINED = "DEFAULT_TASK_LIST_UNDEFINED"
    DEFAULT_TASK_START_TO_CLOSE_TIMEOUT_UNDEFINED = "DEFAULT_TASK_START_TO_CLOSE_TIMEOUT_UNDEFINED"
    DEFAULT_CHILD_POLICY_UNDEFINED = "DEFAULT_CHILD_POLICY_UNDEFINED"
    OPERATION_NOT_PERMITTED = "OPERATION_NOT_PERMITTED"


class StartLambdaFunctionFailedCause(StrEnum):
    ASSUME_ROLE_FAILED = "ASSUME_ROLE_FAILED"


class StartTimerFailedCause(StrEnum):
    TIMER_ID_ALREADY_IN_USE = "TIMER_ID_ALREADY_IN_USE"
    OPEN_TIMERS_LIMIT_EXCEEDED = "OPEN_TIMERS_LIMIT_EXCEEDED"
    TIMER_CREATION_RATE_EXCEEDED = "TIMER_CREATION_RATE_EXCEEDED"
    OPERATION_NOT_PERMITTED = "OPERATION_NOT_PERMITTED"


class WorkflowExecutionCancelRequestedCause(StrEnum):
    CHILD_POLICY_APPLIED = "CHILD_POLICY_APPLIED"


class WorkflowExecutionTerminatedCause(StrEnum):
    CHILD_POLICY_APPLIED = "CHILD_POLICY_APPLIED"
    EVENT_LIMIT_EXCEEDED = "EVENT_LIMIT_EXCEEDED"
    OPERATOR_INITIATED = "OPERATOR_INITIATED"


class WorkflowExecutionTimeoutType(StrEnum):
    START_TO_CLOSE = "START_TO_CLOSE"


class DefaultUndefinedFault(ServiceException):
    code: str = "DefaultUndefinedFault"
    sender_fault: bool = False
    status_code: int = 400


class DomainAlreadyExistsFault(ServiceException):
    code: str = "DomainAlreadyExistsFault"
    sender_fault: bool = False
    status_code: int = 400


class DomainDeprecatedFault(ServiceException):
    code: str = "DomainDeprecatedFault"
    sender_fault: bool = False
    status_code: int = 400


class LimitExceededFault(ServiceException):
    code: str = "LimitExceededFault"
    sender_fault: bool = False
    status_code: int = 400


class OperationNotPermittedFault(ServiceException):
    code: str = "OperationNotPermittedFault"
    sender_fault: bool = False
    status_code: int = 400


class TooManyTagsFault(ServiceException):
    code: str = "TooManyTagsFault"
    sender_fault: bool = False
    status_code: int = 400


class TypeAlreadyExistsFault(ServiceException):
    code: str = "TypeAlreadyExistsFault"
    sender_fault: bool = False
    status_code: int = 400


class TypeDeprecatedFault(ServiceException):
    code: str = "TypeDeprecatedFault"
    sender_fault: bool = False
    status_code: int = 400


class TypeNotDeprecatedFault(ServiceException):
    code: str = "TypeNotDeprecatedFault"
    sender_fault: bool = False
    status_code: int = 400


class UnknownResourceFault(ServiceException):
    code: str = "UnknownResourceFault"
    sender_fault: bool = False
    status_code: int = 400


class WorkflowExecutionAlreadyStartedFault(ServiceException):
    code: str = "WorkflowExecutionAlreadyStartedFault"
    sender_fault: bool = False
    status_code: int = 400


class ActivityType(TypedDict, total=False):
    name: Name
    version: Version


class WorkflowExecution(TypedDict, total=False):
    workflowId: WorkflowId
    runId: WorkflowRunId


EventId = int


class ActivityTask(TypedDict, total=False):
    taskToken: TaskToken
    activityId: ActivityId
    startedEventId: EventId
    workflowExecution: WorkflowExecution
    activityType: ActivityType
    input: Data | None


class ActivityTaskCancelRequestedEventAttributes(TypedDict, total=False):
    decisionTaskCompletedEventId: EventId
    activityId: ActivityId


class ActivityTaskCanceledEventAttributes(TypedDict, total=False):
    details: Data | None
    scheduledEventId: EventId
    startedEventId: EventId
    latestCancelRequestedEventId: EventId | None


class ActivityTaskCompletedEventAttributes(TypedDict, total=False):
    result: Data | None
    scheduledEventId: EventId
    startedEventId: EventId


class ActivityTaskFailedEventAttributes(TypedDict, total=False):
    reason: FailureReason | None
    details: Data | None
    scheduledEventId: EventId
    startedEventId: EventId


class TaskList(TypedDict, total=False):
    name: Name


class ActivityTaskScheduledEventAttributes(TypedDict, total=False):
    activityType: ActivityType
    activityId: ActivityId
    input: Data | None
    control: Data | None
    scheduleToStartTimeout: DurationInSecondsOptional | None
    scheduleToCloseTimeout: DurationInSecondsOptional | None
    startToCloseTimeout: DurationInSecondsOptional | None
    taskList: TaskList
    taskPriority: TaskPriority | None
    decisionTaskCompletedEventId: EventId
    heartbeatTimeout: DurationInSecondsOptional | None


class ActivityTaskStartedEventAttributes(TypedDict, total=False):
    identity: Identity | None
    scheduledEventId: EventId


class ActivityTaskStatus(TypedDict, total=False):
    cancelRequested: Canceled


class ActivityTaskTimedOutEventAttributes(TypedDict, total=False):
    timeoutType: ActivityTaskTimeoutType
    scheduledEventId: EventId
    startedEventId: EventId
    details: LimitedData | None


class ActivityTypeConfiguration(TypedDict, total=False):
    defaultTaskStartToCloseTimeout: DurationInSecondsOptional | None
    defaultTaskHeartbeatTimeout: DurationInSecondsOptional | None
    defaultTaskList: TaskList | None
    defaultTaskPriority: TaskPriority | None
    defaultTaskScheduleToStartTimeout: DurationInSecondsOptional | None
    defaultTaskScheduleToCloseTimeout: DurationInSecondsOptional | None


Timestamp = datetime


class ActivityTypeInfo(TypedDict, total=False):
    activityType: ActivityType
    status: RegistrationStatus
    description: Description | None
    creationDate: Timestamp
    deprecationDate: Timestamp | None


class ActivityTypeDetail(TypedDict, total=False):
    typeInfo: ActivityTypeInfo
    configuration: ActivityTypeConfiguration


ActivityTypeInfoList = list[ActivityTypeInfo]


class ActivityTypeInfos(TypedDict, total=False):
    typeInfos: ActivityTypeInfoList
    nextPageToken: PageToken | None


class CancelTimerDecisionAttributes(TypedDict, total=False):
    timerId: TimerId


class CancelTimerFailedEventAttributes(TypedDict, total=False):
    timerId: TimerId
    cause: CancelTimerFailedCause
    decisionTaskCompletedEventId: EventId


class CancelWorkflowExecutionDecisionAttributes(TypedDict, total=False):
    details: Data | None


class CancelWorkflowExecutionFailedEventAttributes(TypedDict, total=False):
    cause: CancelWorkflowExecutionFailedCause
    decisionTaskCompletedEventId: EventId


class WorkflowType(TypedDict, total=False):
    name: Name
    version: Version


class ChildWorkflowExecutionCanceledEventAttributes(TypedDict, total=False):
    workflowExecution: WorkflowExecution
    workflowType: WorkflowType
    details: Data | None
    initiatedEventId: EventId
    startedEventId: EventId


class ChildWorkflowExecutionCompletedEventAttributes(TypedDict, total=False):
    workflowExecution: WorkflowExecution
    workflowType: WorkflowType
    result: Data | None
    initiatedEventId: EventId
    startedEventId: EventId


class ChildWorkflowExecutionFailedEventAttributes(TypedDict, total=False):
    workflowExecution: WorkflowExecution
    workflowType: WorkflowType
    reason: FailureReason | None
    details: Data | None
    initiatedEventId: EventId
    startedEventId: EventId


class ChildWorkflowExecutionStartedEventAttributes(TypedDict, total=False):
    workflowExecution: WorkflowExecution
    workflowType: WorkflowType
    initiatedEventId: EventId


class ChildWorkflowExecutionTerminatedEventAttributes(TypedDict, total=False):
    workflowExecution: WorkflowExecution
    workflowType: WorkflowType
    initiatedEventId: EventId
    startedEventId: EventId


class ChildWorkflowExecutionTimedOutEventAttributes(TypedDict, total=False):
    workflowExecution: WorkflowExecution
    workflowType: WorkflowType
    timeoutType: WorkflowExecutionTimeoutType
    initiatedEventId: EventId
    startedEventId: EventId


class CloseStatusFilter(TypedDict, total=False):
    status: CloseStatus


class CompleteWorkflowExecutionDecisionAttributes(TypedDict, total=False):
    result: Data | None


class CompleteWorkflowExecutionFailedEventAttributes(TypedDict, total=False):
    cause: CompleteWorkflowExecutionFailedCause
    decisionTaskCompletedEventId: EventId


TagList = list[Tag]


class ContinueAsNewWorkflowExecutionDecisionAttributes(TypedDict, total=False):
    input: Data | None
    executionStartToCloseTimeout: DurationInSecondsOptional | None
    taskList: TaskList | None
    taskPriority: TaskPriority | None
    taskStartToCloseTimeout: DurationInSecondsOptional | None
    childPolicy: ChildPolicy | None
    tagList: TagList | None
    workflowTypeVersion: Version | None
    lambdaRole: Arn | None


class ContinueAsNewWorkflowExecutionFailedEventAttributes(TypedDict, total=False):
    cause: ContinueAsNewWorkflowExecutionFailedCause
    decisionTaskCompletedEventId: EventId


class TagFilter(TypedDict, total=False):
    tag: Tag


class WorkflowTypeFilter(TypedDict, total=False):
    name: Name
    version: VersionOptional | None


class WorkflowExecutionFilter(TypedDict, total=False):
    workflowId: WorkflowId


class ExecutionTimeFilter(TypedDict, total=False):
    oldestDate: Timestamp
    latestDate: Timestamp | None


class CountClosedWorkflowExecutionsInput(ServiceRequest):
    domain: DomainName
    startTimeFilter: ExecutionTimeFilter | None
    closeTimeFilter: ExecutionTimeFilter | None
    executionFilter: WorkflowExecutionFilter | None
    typeFilter: WorkflowTypeFilter | None
    tagFilter: TagFilter | None
    closeStatusFilter: CloseStatusFilter | None


class CountOpenWorkflowExecutionsInput(ServiceRequest):
    domain: DomainName
    startTimeFilter: ExecutionTimeFilter
    typeFilter: WorkflowTypeFilter | None
    tagFilter: TagFilter | None
    executionFilter: WorkflowExecutionFilter | None


class CountPendingActivityTasksInput(ServiceRequest):
    domain: DomainName
    taskList: TaskList


class CountPendingDecisionTasksInput(ServiceRequest):
    domain: DomainName
    taskList: TaskList


class ScheduleLambdaFunctionDecisionAttributes(TypedDict, total=False):
    id: FunctionId
    name: FunctionName
    control: Data | None
    input: FunctionInput | None
    startToCloseTimeout: DurationInSecondsOptional | None


class StartChildWorkflowExecutionDecisionAttributes(TypedDict, total=False):
    workflowType: WorkflowType
    workflowId: WorkflowId
    control: Data | None
    input: Data | None
    executionStartToCloseTimeout: DurationInSecondsOptional | None
    taskList: TaskList | None
    taskPriority: TaskPriority | None
    taskStartToCloseTimeout: DurationInSecondsOptional | None
    childPolicy: ChildPolicy | None
    tagList: TagList | None
    lambdaRole: Arn | None


class RequestCancelExternalWorkflowExecutionDecisionAttributes(TypedDict, total=False):
    workflowId: WorkflowId
    runId: WorkflowRunIdOptional | None
    control: Data | None


class SignalExternalWorkflowExecutionDecisionAttributes(TypedDict, total=False):
    workflowId: WorkflowId
    runId: WorkflowRunIdOptional | None
    signalName: SignalName
    input: Data | None
    control: Data | None


class StartTimerDecisionAttributes(TypedDict, total=False):
    timerId: TimerId
    control: Data | None
    startToFireTimeout: DurationInSeconds


class RecordMarkerDecisionAttributes(TypedDict, total=False):
    markerName: MarkerName
    details: Data | None


class FailWorkflowExecutionDecisionAttributes(TypedDict, total=False):
    reason: FailureReason | None
    details: Data | None


class RequestCancelActivityTaskDecisionAttributes(TypedDict, total=False):
    activityId: ActivityId


class ScheduleActivityTaskDecisionAttributes(TypedDict, total=False):
    activityType: ActivityType
    activityId: ActivityId
    control: Data | None
    input: Data | None
    scheduleToCloseTimeout: DurationInSecondsOptional | None
    taskList: TaskList | None
    taskPriority: TaskPriority | None
    scheduleToStartTimeout: DurationInSecondsOptional | None
    startToCloseTimeout: DurationInSecondsOptional | None
    heartbeatTimeout: DurationInSecondsOptional | None


class Decision(TypedDict, total=False):
    decisionType: DecisionType
    scheduleActivityTaskDecisionAttributes: ScheduleActivityTaskDecisionAttributes | None
    requestCancelActivityTaskDecisionAttributes: RequestCancelActivityTaskDecisionAttributes | None
    completeWorkflowExecutionDecisionAttributes: CompleteWorkflowExecutionDecisionAttributes | None
    failWorkflowExecutionDecisionAttributes: FailWorkflowExecutionDecisionAttributes | None
    cancelWorkflowExecutionDecisionAttributes: CancelWorkflowExecutionDecisionAttributes | None
    continueAsNewWorkflowExecutionDecisionAttributes: (
        ContinueAsNewWorkflowExecutionDecisionAttributes | None
    )
    recordMarkerDecisionAttributes: RecordMarkerDecisionAttributes | None
    startTimerDecisionAttributes: StartTimerDecisionAttributes | None
    cancelTimerDecisionAttributes: CancelTimerDecisionAttributes | None
    signalExternalWorkflowExecutionDecisionAttributes: (
        SignalExternalWorkflowExecutionDecisionAttributes | None
    )
    requestCancelExternalWorkflowExecutionDecisionAttributes: (
        RequestCancelExternalWorkflowExecutionDecisionAttributes | None
    )
    startChildWorkflowExecutionDecisionAttributes: (
        StartChildWorkflowExecutionDecisionAttributes | None
    )
    scheduleLambdaFunctionDecisionAttributes: ScheduleLambdaFunctionDecisionAttributes | None


DecisionList = list[Decision]


class StartLambdaFunctionFailedEventAttributes(TypedDict, total=False):
    scheduledEventId: EventId | None
    cause: StartLambdaFunctionFailedCause | None
    message: CauseMessage | None


class ScheduleLambdaFunctionFailedEventAttributes(TypedDict, total=False):
    id: FunctionId
    name: FunctionName
    cause: ScheduleLambdaFunctionFailedCause
    decisionTaskCompletedEventId: EventId


class LambdaFunctionTimedOutEventAttributes(TypedDict, total=False):
    scheduledEventId: EventId
    startedEventId: EventId
    timeoutType: LambdaFunctionTimeoutType | None


class LambdaFunctionFailedEventAttributes(TypedDict, total=False):
    scheduledEventId: EventId
    startedEventId: EventId
    reason: FailureReason | None
    details: Data | None


class LambdaFunctionCompletedEventAttributes(TypedDict, total=False):
    scheduledEventId: EventId
    startedEventId: EventId
    result: Data | None


class LambdaFunctionStartedEventAttributes(TypedDict, total=False):
    scheduledEventId: EventId


class LambdaFunctionScheduledEventAttributes(TypedDict, total=False):
    id: FunctionId
    name: FunctionName
    control: Data | None
    input: FunctionInput | None
    startToCloseTimeout: DurationInSecondsOptional | None
    decisionTaskCompletedEventId: EventId


class StartChildWorkflowExecutionFailedEventAttributes(TypedDict, total=False):
    workflowType: WorkflowType
    cause: StartChildWorkflowExecutionFailedCause
    workflowId: WorkflowId
    initiatedEventId: EventId
    decisionTaskCompletedEventId: EventId
    control: Data | None


class StartTimerFailedEventAttributes(TypedDict, total=False):
    timerId: TimerId
    cause: StartTimerFailedCause
    decisionTaskCompletedEventId: EventId


class RequestCancelActivityTaskFailedEventAttributes(TypedDict, total=False):
    activityId: ActivityId
    cause: RequestCancelActivityTaskFailedCause
    decisionTaskCompletedEventId: EventId


class ScheduleActivityTaskFailedEventAttributes(TypedDict, total=False):
    activityType: ActivityType
    activityId: ActivityId
    cause: ScheduleActivityTaskFailedCause
    decisionTaskCompletedEventId: EventId


class RequestCancelExternalWorkflowExecutionFailedEventAttributes(TypedDict, total=False):
    workflowId: WorkflowId
    runId: WorkflowRunIdOptional | None
    cause: RequestCancelExternalWorkflowExecutionFailedCause
    initiatedEventId: EventId
    decisionTaskCompletedEventId: EventId
    control: Data | None


class RequestCancelExternalWorkflowExecutionInitiatedEventAttributes(TypedDict, total=False):
    workflowId: WorkflowId
    runId: WorkflowRunIdOptional | None
    decisionTaskCompletedEventId: EventId
    control: Data | None


class ExternalWorkflowExecutionCancelRequestedEventAttributes(TypedDict, total=False):
    workflowExecution: WorkflowExecution
    initiatedEventId: EventId


class SignalExternalWorkflowExecutionFailedEventAttributes(TypedDict, total=False):
    workflowId: WorkflowId
    runId: WorkflowRunIdOptional | None
    cause: SignalExternalWorkflowExecutionFailedCause
    initiatedEventId: EventId
    decisionTaskCompletedEventId: EventId
    control: Data | None


class ExternalWorkflowExecutionSignaledEventAttributes(TypedDict, total=False):
    workflowExecution: WorkflowExecution
    initiatedEventId: EventId


class SignalExternalWorkflowExecutionInitiatedEventAttributes(TypedDict, total=False):
    workflowId: WorkflowId
    runId: WorkflowRunIdOptional | None
    signalName: SignalName
    input: Data | None
    decisionTaskCompletedEventId: EventId
    control: Data | None


class StartChildWorkflowExecutionInitiatedEventAttributes(TypedDict, total=False):
    workflowId: WorkflowId
    workflowType: WorkflowType
    control: Data | None
    input: Data | None
    executionStartToCloseTimeout: DurationInSecondsOptional | None
    taskList: TaskList
    taskPriority: TaskPriority | None
    decisionTaskCompletedEventId: EventId
    childPolicy: ChildPolicy
    taskStartToCloseTimeout: DurationInSecondsOptional | None
    tagList: TagList | None
    lambdaRole: Arn | None


class TimerCanceledEventAttributes(TypedDict, total=False):
    timerId: TimerId
    startedEventId: EventId
    decisionTaskCompletedEventId: EventId


class TimerFiredEventAttributes(TypedDict, total=False):
    timerId: TimerId
    startedEventId: EventId


class TimerStartedEventAttributes(TypedDict, total=False):
    timerId: TimerId
    control: Data | None
    startToFireTimeout: DurationInSeconds
    decisionTaskCompletedEventId: EventId


class RecordMarkerFailedEventAttributes(TypedDict, total=False):
    markerName: MarkerName
    cause: RecordMarkerFailedCause
    decisionTaskCompletedEventId: EventId


class MarkerRecordedEventAttributes(TypedDict, total=False):
    markerName: MarkerName
    details: Data | None
    decisionTaskCompletedEventId: EventId


class WorkflowExecutionSignaledEventAttributes(TypedDict, total=False):
    signalName: SignalName
    input: Data | None
    externalWorkflowExecution: WorkflowExecution | None
    externalInitiatedEventId: EventId | None


class DecisionTaskTimedOutEventAttributes(TypedDict, total=False):
    timeoutType: DecisionTaskTimeoutType
    scheduledEventId: EventId
    startedEventId: EventId


class DecisionTaskCompletedEventAttributes(TypedDict, total=False):
    executionContext: Data | None
    scheduledEventId: EventId
    startedEventId: EventId
    taskList: TaskList | None
    taskListScheduleToStartTimeout: DurationInSecondsOptional | None


class DecisionTaskStartedEventAttributes(TypedDict, total=False):
    identity: Identity | None
    scheduledEventId: EventId


class DecisionTaskScheduledEventAttributes(TypedDict, total=False):
    taskList: TaskList
    taskPriority: TaskPriority | None
    startToCloseTimeout: DurationInSecondsOptional | None
    scheduleToStartTimeout: DurationInSecondsOptional | None


class WorkflowExecutionCancelRequestedEventAttributes(TypedDict, total=False):
    externalWorkflowExecution: WorkflowExecution | None
    externalInitiatedEventId: EventId | None
    cause: WorkflowExecutionCancelRequestedCause | None


class WorkflowExecutionTerminatedEventAttributes(TypedDict, total=False):
    reason: TerminateReason | None
    details: Data | None
    childPolicy: ChildPolicy
    cause: WorkflowExecutionTerminatedCause | None


class WorkflowExecutionContinuedAsNewEventAttributes(TypedDict, total=False):
    input: Data | None
    decisionTaskCompletedEventId: EventId
    newExecutionRunId: WorkflowRunId
    executionStartToCloseTimeout: DurationInSecondsOptional | None
    taskList: TaskList
    taskPriority: TaskPriority | None
    taskStartToCloseTimeout: DurationInSecondsOptional | None
    childPolicy: ChildPolicy
    tagList: TagList | None
    workflowType: WorkflowType
    lambdaRole: Arn | None


class WorkflowExecutionCanceledEventAttributes(TypedDict, total=False):
    details: Data | None
    decisionTaskCompletedEventId: EventId


class WorkflowExecutionTimedOutEventAttributes(TypedDict, total=False):
    timeoutType: WorkflowExecutionTimeoutType
    childPolicy: ChildPolicy


class FailWorkflowExecutionFailedEventAttributes(TypedDict, total=False):
    cause: FailWorkflowExecutionFailedCause
    decisionTaskCompletedEventId: EventId


class WorkflowExecutionFailedEventAttributes(TypedDict, total=False):
    reason: FailureReason | None
    details: Data | None
    decisionTaskCompletedEventId: EventId


class WorkflowExecutionCompletedEventAttributes(TypedDict, total=False):
    result: Data | None
    decisionTaskCompletedEventId: EventId


class WorkflowExecutionStartedEventAttributes(TypedDict, total=False):
    input: Data | None
    executionStartToCloseTimeout: DurationInSecondsOptional | None
    taskStartToCloseTimeout: DurationInSecondsOptional | None
    childPolicy: ChildPolicy
    taskList: TaskList
    taskPriority: TaskPriority | None
    workflowType: WorkflowType
    tagList: TagList | None
    continuedExecutionRunId: WorkflowRunIdOptional | None
    parentWorkflowExecution: WorkflowExecution | None
    parentInitiatedEventId: EventId | None
    lambdaRole: Arn | None


class HistoryEvent(TypedDict, total=False):
    eventTimestamp: Timestamp
    eventType: EventType
    eventId: EventId
    workflowExecutionStartedEventAttributes: WorkflowExecutionStartedEventAttributes | None
    workflowExecutionCompletedEventAttributes: WorkflowExecutionCompletedEventAttributes | None
    completeWorkflowExecutionFailedEventAttributes: (
        CompleteWorkflowExecutionFailedEventAttributes | None
    )
    workflowExecutionFailedEventAttributes: WorkflowExecutionFailedEventAttributes | None
    failWorkflowExecutionFailedEventAttributes: FailWorkflowExecutionFailedEventAttributes | None
    workflowExecutionTimedOutEventAttributes: WorkflowExecutionTimedOutEventAttributes | None
    workflowExecutionCanceledEventAttributes: WorkflowExecutionCanceledEventAttributes | None
    cancelWorkflowExecutionFailedEventAttributes: (
        CancelWorkflowExecutionFailedEventAttributes | None
    )
    workflowExecutionContinuedAsNewEventAttributes: (
        WorkflowExecutionContinuedAsNewEventAttributes | None
    )
    continueAsNewWorkflowExecutionFailedEventAttributes: (
        ContinueAsNewWorkflowExecutionFailedEventAttributes | None
    )
    workflowExecutionTerminatedEventAttributes: WorkflowExecutionTerminatedEventAttributes | None
    workflowExecutionCancelRequestedEventAttributes: (
        WorkflowExecutionCancelRequestedEventAttributes | None
    )
    decisionTaskScheduledEventAttributes: DecisionTaskScheduledEventAttributes | None
    decisionTaskStartedEventAttributes: DecisionTaskStartedEventAttributes | None
    decisionTaskCompletedEventAttributes: DecisionTaskCompletedEventAttributes | None
    decisionTaskTimedOutEventAttributes: DecisionTaskTimedOutEventAttributes | None
    activityTaskScheduledEventAttributes: ActivityTaskScheduledEventAttributes | None
    activityTaskStartedEventAttributes: ActivityTaskStartedEventAttributes | None
    activityTaskCompletedEventAttributes: ActivityTaskCompletedEventAttributes | None
    activityTaskFailedEventAttributes: ActivityTaskFailedEventAttributes | None
    activityTaskTimedOutEventAttributes: ActivityTaskTimedOutEventAttributes | None
    activityTaskCanceledEventAttributes: ActivityTaskCanceledEventAttributes | None
    activityTaskCancelRequestedEventAttributes: ActivityTaskCancelRequestedEventAttributes | None
    workflowExecutionSignaledEventAttributes: WorkflowExecutionSignaledEventAttributes | None
    markerRecordedEventAttributes: MarkerRecordedEventAttributes | None
    recordMarkerFailedEventAttributes: RecordMarkerFailedEventAttributes | None
    timerStartedEventAttributes: TimerStartedEventAttributes | None
    timerFiredEventAttributes: TimerFiredEventAttributes | None
    timerCanceledEventAttributes: TimerCanceledEventAttributes | None
    startChildWorkflowExecutionInitiatedEventAttributes: (
        StartChildWorkflowExecutionInitiatedEventAttributes | None
    )
    childWorkflowExecutionStartedEventAttributes: (
        ChildWorkflowExecutionStartedEventAttributes | None
    )
    childWorkflowExecutionCompletedEventAttributes: (
        ChildWorkflowExecutionCompletedEventAttributes | None
    )
    childWorkflowExecutionFailedEventAttributes: ChildWorkflowExecutionFailedEventAttributes | None
    childWorkflowExecutionTimedOutEventAttributes: (
        ChildWorkflowExecutionTimedOutEventAttributes | None
    )
    childWorkflowExecutionCanceledEventAttributes: (
        ChildWorkflowExecutionCanceledEventAttributes | None
    )
    childWorkflowExecutionTerminatedEventAttributes: (
        ChildWorkflowExecutionTerminatedEventAttributes | None
    )
    signalExternalWorkflowExecutionInitiatedEventAttributes: (
        SignalExternalWorkflowExecutionInitiatedEventAttributes | None
    )
    externalWorkflowExecutionSignaledEventAttributes: (
        ExternalWorkflowExecutionSignaledEventAttributes | None
    )
    signalExternalWorkflowExecutionFailedEventAttributes: (
        SignalExternalWorkflowExecutionFailedEventAttributes | None
    )
    externalWorkflowExecutionCancelRequestedEventAttributes: (
        ExternalWorkflowExecutionCancelRequestedEventAttributes | None
    )
    requestCancelExternalWorkflowExecutionInitiatedEventAttributes: (
        RequestCancelExternalWorkflowExecutionInitiatedEventAttributes | None
    )
    requestCancelExternalWorkflowExecutionFailedEventAttributes: (
        RequestCancelExternalWorkflowExecutionFailedEventAttributes | None
    )
    scheduleActivityTaskFailedEventAttributes: ScheduleActivityTaskFailedEventAttributes | None
    requestCancelActivityTaskFailedEventAttributes: (
        RequestCancelActivityTaskFailedEventAttributes | None
    )
    startTimerFailedEventAttributes: StartTimerFailedEventAttributes | None
    cancelTimerFailedEventAttributes: CancelTimerFailedEventAttributes | None
    startChildWorkflowExecutionFailedEventAttributes: (
        StartChildWorkflowExecutionFailedEventAttributes | None
    )
    lambdaFunctionScheduledEventAttributes: LambdaFunctionScheduledEventAttributes | None
    lambdaFunctionStartedEventAttributes: LambdaFunctionStartedEventAttributes | None
    lambdaFunctionCompletedEventAttributes: LambdaFunctionCompletedEventAttributes | None
    lambdaFunctionFailedEventAttributes: LambdaFunctionFailedEventAttributes | None
    lambdaFunctionTimedOutEventAttributes: LambdaFunctionTimedOutEventAttributes | None
    scheduleLambdaFunctionFailedEventAttributes: ScheduleLambdaFunctionFailedEventAttributes | None
    startLambdaFunctionFailedEventAttributes: StartLambdaFunctionFailedEventAttributes | None


HistoryEventList = list[HistoryEvent]


class DecisionTask(TypedDict, total=False):
    taskToken: TaskToken
    startedEventId: EventId
    workflowExecution: WorkflowExecution
    workflowType: WorkflowType
    events: HistoryEventList
    nextPageToken: PageToken | None
    previousStartedEventId: EventId | None


class DeleteActivityTypeInput(ServiceRequest):
    domain: DomainName
    activityType: ActivityType


class DeleteWorkflowTypeInput(ServiceRequest):
    domain: DomainName
    workflowType: WorkflowType


class DeprecateActivityTypeInput(ServiceRequest):
    domain: DomainName
    activityType: ActivityType


class DeprecateDomainInput(ServiceRequest):
    name: DomainName


class DeprecateWorkflowTypeInput(ServiceRequest):
    domain: DomainName
    workflowType: WorkflowType


class DescribeActivityTypeInput(ServiceRequest):
    domain: DomainName
    activityType: ActivityType


class DescribeDomainInput(ServiceRequest):
    name: DomainName


class DescribeWorkflowExecutionInput(ServiceRequest):
    domain: DomainName
    execution: WorkflowExecution


class DescribeWorkflowTypeInput(ServiceRequest):
    domain: DomainName
    workflowType: WorkflowType


class DomainConfiguration(TypedDict, total=False):
    workflowExecutionRetentionPeriodInDays: DurationInDays


class DomainInfo(TypedDict, total=False):
    name: DomainName
    status: RegistrationStatus
    description: Description | None
    arn: Arn | None


class DomainDetail(TypedDict, total=False):
    domainInfo: DomainInfo
    configuration: DomainConfiguration


DomainInfoList = list[DomainInfo]


class DomainInfos(TypedDict, total=False):
    domainInfos: DomainInfoList
    nextPageToken: PageToken | None


class GetWorkflowExecutionHistoryInput(ServiceRequest):
    domain: DomainName
    execution: WorkflowExecution
    nextPageToken: PageToken | None
    maximumPageSize: PageSize | None
    reverseOrder: ReverseOrder | None


class History(TypedDict, total=False):
    events: HistoryEventList
    nextPageToken: PageToken | None


class ListActivityTypesInput(ServiceRequest):
    domain: DomainName
    name: Name | None
    registrationStatus: RegistrationStatus
    nextPageToken: PageToken | None
    maximumPageSize: PageSize | None
    reverseOrder: ReverseOrder | None


class ListClosedWorkflowExecutionsInput(ServiceRequest):
    domain: DomainName
    startTimeFilter: ExecutionTimeFilter | None
    closeTimeFilter: ExecutionTimeFilter | None
    executionFilter: WorkflowExecutionFilter | None
    closeStatusFilter: CloseStatusFilter | None
    typeFilter: WorkflowTypeFilter | None
    tagFilter: TagFilter | None
    nextPageToken: PageToken | None
    maximumPageSize: PageSize | None
    reverseOrder: ReverseOrder | None


class ListDomainsInput(ServiceRequest):
    nextPageToken: PageToken | None
    registrationStatus: RegistrationStatus
    maximumPageSize: PageSize | None
    reverseOrder: ReverseOrder | None


class ListOpenWorkflowExecutionsInput(ServiceRequest):
    domain: DomainName
    startTimeFilter: ExecutionTimeFilter
    typeFilter: WorkflowTypeFilter | None
    tagFilter: TagFilter | None
    nextPageToken: PageToken | None
    maximumPageSize: PageSize | None
    reverseOrder: ReverseOrder | None
    executionFilter: WorkflowExecutionFilter | None


class ListTagsForResourceInput(ServiceRequest):
    resourceArn: Arn


class ResourceTag(TypedDict, total=False):
    key: ResourceTagKey
    value: ResourceTagValue | None


ResourceTagList = list[ResourceTag]


class ListTagsForResourceOutput(TypedDict, total=False):
    tags: ResourceTagList | None


class ListWorkflowTypesInput(ServiceRequest):
    domain: DomainName
    name: Name | None
    registrationStatus: RegistrationStatus
    nextPageToken: PageToken | None
    maximumPageSize: PageSize | None
    reverseOrder: ReverseOrder | None


class PendingTaskCount(TypedDict, total=False):
    count: Count
    truncated: Truncated | None


class PollForActivityTaskInput(ServiceRequest):
    domain: DomainName
    taskList: TaskList
    identity: Identity | None


class PollForDecisionTaskInput(ServiceRequest):
    domain: DomainName
    taskList: TaskList
    identity: Identity | None
    nextPageToken: PageToken | None
    maximumPageSize: PageSize | None
    reverseOrder: ReverseOrder | None
    startAtPreviousStartedEvent: StartAtPreviousStartedEvent | None


class RecordActivityTaskHeartbeatInput(ServiceRequest):
    taskToken: TaskToken
    details: LimitedData | None


class RegisterActivityTypeInput(ServiceRequest):
    domain: DomainName
    name: Name
    version: Version
    description: Description | None
    defaultTaskStartToCloseTimeout: DurationInSecondsOptional | None
    defaultTaskHeartbeatTimeout: DurationInSecondsOptional | None
    defaultTaskList: TaskList | None
    defaultTaskPriority: TaskPriority | None
    defaultTaskScheduleToStartTimeout: DurationInSecondsOptional | None
    defaultTaskScheduleToCloseTimeout: DurationInSecondsOptional | None


class RegisterDomainInput(ServiceRequest):
    name: DomainName
    description: Description | None
    workflowExecutionRetentionPeriodInDays: DurationInDays
    tags: ResourceTagList | None


class RegisterWorkflowTypeInput(ServiceRequest):
    domain: DomainName
    name: Name
    version: Version
    description: Description | None
    defaultTaskStartToCloseTimeout: DurationInSecondsOptional | None
    defaultExecutionStartToCloseTimeout: DurationInSecondsOptional | None
    defaultTaskList: TaskList | None
    defaultTaskPriority: TaskPriority | None
    defaultChildPolicy: ChildPolicy | None
    defaultLambdaRole: Arn | None


class RequestCancelWorkflowExecutionInput(ServiceRequest):
    domain: DomainName
    workflowId: WorkflowId
    runId: WorkflowRunIdOptional | None


ResourceTagKeyList = list[ResourceTagKey]


class RespondActivityTaskCanceledInput(ServiceRequest):
    taskToken: TaskToken
    details: Data | None


class RespondActivityTaskCompletedInput(ServiceRequest):
    taskToken: TaskToken
    result: Data | None


class RespondActivityTaskFailedInput(ServiceRequest):
    taskToken: TaskToken
    reason: FailureReason | None
    details: Data | None


class RespondDecisionTaskCompletedInput(ServiceRequest):
    taskToken: TaskToken
    decisions: DecisionList | None
    executionContext: Data | None
    taskList: TaskList | None
    taskListScheduleToStartTimeout: DurationInSecondsOptional | None


class Run(TypedDict, total=False):
    runId: WorkflowRunId | None


class SignalWorkflowExecutionInput(ServiceRequest):
    domain: DomainName
    workflowId: WorkflowId
    runId: WorkflowRunIdOptional | None
    signalName: SignalName
    input: Data | None


class StartWorkflowExecutionInput(ServiceRequest):
    domain: DomainName
    workflowId: WorkflowId
    workflowType: WorkflowType
    taskList: TaskList | None
    taskPriority: TaskPriority | None
    input: Data | None
    executionStartToCloseTimeout: DurationInSecondsOptional | None
    tagList: TagList | None
    taskStartToCloseTimeout: DurationInSecondsOptional | None
    childPolicy: ChildPolicy | None
    lambdaRole: Arn | None


class TagResourceInput(ServiceRequest):
    resourceArn: Arn
    tags: ResourceTagList


class TerminateWorkflowExecutionInput(ServiceRequest):
    domain: DomainName
    workflowId: WorkflowId
    runId: WorkflowRunIdOptional | None
    reason: TerminateReason | None
    details: Data | None
    childPolicy: ChildPolicy | None


class UndeprecateActivityTypeInput(ServiceRequest):
    domain: DomainName
    activityType: ActivityType


class UndeprecateDomainInput(ServiceRequest):
    name: DomainName


class UndeprecateWorkflowTypeInput(ServiceRequest):
    domain: DomainName
    workflowType: WorkflowType


class UntagResourceInput(ServiceRequest):
    resourceArn: Arn
    tagKeys: ResourceTagKeyList


class WorkflowExecutionConfiguration(TypedDict, total=False):
    taskStartToCloseTimeout: DurationInSeconds
    executionStartToCloseTimeout: DurationInSeconds
    taskList: TaskList
    taskPriority: TaskPriority | None
    childPolicy: ChildPolicy
    lambdaRole: Arn | None


class WorkflowExecutionCount(TypedDict, total=False):
    count: Count
    truncated: Truncated | None


class WorkflowExecutionOpenCounts(TypedDict, total=False):
    openActivityTasks: Count
    openDecisionTasks: OpenDecisionTasksCount
    openTimers: Count
    openChildWorkflowExecutions: Count
    openLambdaFunctions: Count | None


class WorkflowExecutionInfo(TypedDict, total=False):
    execution: WorkflowExecution
    workflowType: WorkflowType
    startTimestamp: Timestamp
    closeTimestamp: Timestamp | None
    executionStatus: ExecutionStatus
    closeStatus: CloseStatus | None
    parent: WorkflowExecution | None
    tagList: TagList | None
    cancelRequested: Canceled | None


class WorkflowExecutionDetail(TypedDict, total=False):
    executionInfo: WorkflowExecutionInfo
    executionConfiguration: WorkflowExecutionConfiguration
    openCounts: WorkflowExecutionOpenCounts
    latestActivityTaskTimestamp: Timestamp | None
    latestExecutionContext: Data | None


WorkflowExecutionInfoList = list[WorkflowExecutionInfo]


class WorkflowExecutionInfos(TypedDict, total=False):
    executionInfos: WorkflowExecutionInfoList
    nextPageToken: PageToken | None


class WorkflowTypeConfiguration(TypedDict, total=False):
    defaultTaskStartToCloseTimeout: DurationInSecondsOptional | None
    defaultExecutionStartToCloseTimeout: DurationInSecondsOptional | None
    defaultTaskList: TaskList | None
    defaultTaskPriority: TaskPriority | None
    defaultChildPolicy: ChildPolicy | None
    defaultLambdaRole: Arn | None


class WorkflowTypeInfo(TypedDict, total=False):
    workflowType: WorkflowType
    status: RegistrationStatus
    description: Description | None
    creationDate: Timestamp
    deprecationDate: Timestamp | None


class WorkflowTypeDetail(TypedDict, total=False):
    typeInfo: WorkflowTypeInfo
    configuration: WorkflowTypeConfiguration


WorkflowTypeInfoList = list[WorkflowTypeInfo]


class WorkflowTypeInfos(TypedDict, total=False):
    typeInfos: WorkflowTypeInfoList
    nextPageToken: PageToken | None


class SwfApi:
    service: str = "swf"
    version: str = "2012-01-25"

    @handler("CountClosedWorkflowExecutions")
    def count_closed_workflow_executions(
        self,
        context: RequestContext,
        domain: DomainName,
        start_time_filter: ExecutionTimeFilter | None = None,
        close_time_filter: ExecutionTimeFilter | None = None,
        execution_filter: WorkflowExecutionFilter | None = None,
        type_filter: WorkflowTypeFilter | None = None,
        tag_filter: TagFilter | None = None,
        close_status_filter: CloseStatusFilter | None = None,
        **kwargs,
    ) -> WorkflowExecutionCount:
        raise NotImplementedError

    @handler("CountOpenWorkflowExecutions")
    def count_open_workflow_executions(
        self,
        context: RequestContext,
        domain: DomainName,
        start_time_filter: ExecutionTimeFilter,
        type_filter: WorkflowTypeFilter | None = None,
        tag_filter: TagFilter | None = None,
        execution_filter: WorkflowExecutionFilter | None = None,
        **kwargs,
    ) -> WorkflowExecutionCount:
        raise NotImplementedError

    @handler("CountPendingActivityTasks")
    def count_pending_activity_tasks(
        self, context: RequestContext, domain: DomainName, task_list: TaskList, **kwargs
    ) -> PendingTaskCount:
        raise NotImplementedError

    @handler("CountPendingDecisionTasks")
    def count_pending_decision_tasks(
        self, context: RequestContext, domain: DomainName, task_list: TaskList, **kwargs
    ) -> PendingTaskCount:
        raise NotImplementedError

    @handler("DeleteActivityType")
    def delete_activity_type(
        self, context: RequestContext, domain: DomainName, activity_type: ActivityType, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("DeleteWorkflowType")
    def delete_workflow_type(
        self, context: RequestContext, domain: DomainName, workflow_type: WorkflowType, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("DeprecateActivityType")
    def deprecate_activity_type(
        self, context: RequestContext, domain: DomainName, activity_type: ActivityType, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("DeprecateDomain")
    def deprecate_domain(self, context: RequestContext, name: DomainName, **kwargs) -> None:
        raise NotImplementedError

    @handler("DeprecateWorkflowType")
    def deprecate_workflow_type(
        self, context: RequestContext, domain: DomainName, workflow_type: WorkflowType, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("DescribeActivityType")
    def describe_activity_type(
        self, context: RequestContext, domain: DomainName, activity_type: ActivityType, **kwargs
    ) -> ActivityTypeDetail:
        raise NotImplementedError

    @handler("DescribeDomain")
    def describe_domain(self, context: RequestContext, name: DomainName, **kwargs) -> DomainDetail:
        raise NotImplementedError

    @handler("DescribeWorkflowExecution")
    def describe_workflow_execution(
        self, context: RequestContext, domain: DomainName, execution: WorkflowExecution, **kwargs
    ) -> WorkflowExecutionDetail:
        raise NotImplementedError

    @handler("DescribeWorkflowType")
    def describe_workflow_type(
        self, context: RequestContext, domain: DomainName, workflow_type: WorkflowType, **kwargs
    ) -> WorkflowTypeDetail:
        raise NotImplementedError

    @handler("GetWorkflowExecutionHistory")
    def get_workflow_execution_history(
        self,
        context: RequestContext,
        domain: DomainName,
        execution: WorkflowExecution,
        next_page_token: PageToken | None = None,
        maximum_page_size: PageSize | None = None,
        reverse_order: ReverseOrder | None = None,
        **kwargs,
    ) -> History:
        raise NotImplementedError

    @handler("ListActivityTypes")
    def list_activity_types(
        self,
        context: RequestContext,
        domain: DomainName,
        registration_status: RegistrationStatus,
        name: Name | None = None,
        next_page_token: PageToken | None = None,
        maximum_page_size: PageSize | None = None,
        reverse_order: ReverseOrder | None = None,
        **kwargs,
    ) -> ActivityTypeInfos:
        raise NotImplementedError

    @handler("ListClosedWorkflowExecutions")
    def list_closed_workflow_executions(
        self,
        context: RequestContext,
        domain: DomainName,
        start_time_filter: ExecutionTimeFilter | None = None,
        close_time_filter: ExecutionTimeFilter | None = None,
        execution_filter: WorkflowExecutionFilter | None = None,
        close_status_filter: CloseStatusFilter | None = None,
        type_filter: WorkflowTypeFilter | None = None,
        tag_filter: TagFilter | None = None,
        next_page_token: PageToken | None = None,
        maximum_page_size: PageSize | None = None,
        reverse_order: ReverseOrder | None = None,
        **kwargs,
    ) -> WorkflowExecutionInfos:
        raise NotImplementedError

    @handler("ListDomains")
    def list_domains(
        self,
        context: RequestContext,
        registration_status: RegistrationStatus,
        next_page_token: PageToken | None = None,
        maximum_page_size: PageSize | None = None,
        reverse_order: ReverseOrder | None = None,
        **kwargs,
    ) -> DomainInfos:
        raise NotImplementedError

    @handler("ListOpenWorkflowExecutions")
    def list_open_workflow_executions(
        self,
        context: RequestContext,
        domain: DomainName,
        start_time_filter: ExecutionTimeFilter,
        type_filter: WorkflowTypeFilter | None = None,
        tag_filter: TagFilter | None = None,
        next_page_token: PageToken | None = None,
        maximum_page_size: PageSize | None = None,
        reverse_order: ReverseOrder | None = None,
        execution_filter: WorkflowExecutionFilter | None = None,
        **kwargs,
    ) -> WorkflowExecutionInfos:
        raise NotImplementedError

    @handler("ListTagsForResource")
    def list_tags_for_resource(
        self, context: RequestContext, resource_arn: Arn, **kwargs
    ) -> ListTagsForResourceOutput:
        raise NotImplementedError

    @handler("ListWorkflowTypes")
    def list_workflow_types(
        self,
        context: RequestContext,
        domain: DomainName,
        registration_status: RegistrationStatus,
        name: Name | None = None,
        next_page_token: PageToken | None = None,
        maximum_page_size: PageSize | None = None,
        reverse_order: ReverseOrder | None = None,
        **kwargs,
    ) -> WorkflowTypeInfos:
        raise NotImplementedError

    @handler("PollForActivityTask")
    def poll_for_activity_task(
        self,
        context: RequestContext,
        domain: DomainName,
        task_list: TaskList,
        identity: Identity | None = None,
        **kwargs,
    ) -> ActivityTask:
        raise NotImplementedError

    @handler("PollForDecisionTask")
    def poll_for_decision_task(
        self,
        context: RequestContext,
        domain: DomainName,
        task_list: TaskList,
        identity: Identity | None = None,
        next_page_token: PageToken | None = None,
        maximum_page_size: PageSize | None = None,
        reverse_order: ReverseOrder | None = None,
        start_at_previous_started_event: StartAtPreviousStartedEvent | None = None,
        **kwargs,
    ) -> DecisionTask:
        raise NotImplementedError

    @handler("RecordActivityTaskHeartbeat")
    def record_activity_task_heartbeat(
        self,
        context: RequestContext,
        task_token: TaskToken,
        details: LimitedData | None = None,
        **kwargs,
    ) -> ActivityTaskStatus:
        raise NotImplementedError

    @handler("RegisterActivityType")
    def register_activity_type(
        self,
        context: RequestContext,
        domain: DomainName,
        name: Name,
        version: Version,
        description: Description | None = None,
        default_task_start_to_close_timeout: DurationInSecondsOptional | None = None,
        default_task_heartbeat_timeout: DurationInSecondsOptional | None = None,
        default_task_list: TaskList | None = None,
        default_task_priority: TaskPriority | None = None,
        default_task_schedule_to_start_timeout: DurationInSecondsOptional | None = None,
        default_task_schedule_to_close_timeout: DurationInSecondsOptional | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("RegisterDomain")
    def register_domain(
        self,
        context: RequestContext,
        name: DomainName,
        workflow_execution_retention_period_in_days: DurationInDays,
        description: Description | None = None,
        tags: ResourceTagList | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("RegisterWorkflowType")
    def register_workflow_type(
        self,
        context: RequestContext,
        domain: DomainName,
        name: Name,
        version: Version,
        description: Description | None = None,
        default_task_start_to_close_timeout: DurationInSecondsOptional | None = None,
        default_execution_start_to_close_timeout: DurationInSecondsOptional | None = None,
        default_task_list: TaskList | None = None,
        default_task_priority: TaskPriority | None = None,
        default_child_policy: ChildPolicy | None = None,
        default_lambda_role: Arn | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("RequestCancelWorkflowExecution")
    def request_cancel_workflow_execution(
        self,
        context: RequestContext,
        domain: DomainName,
        workflow_id: WorkflowId,
        run_id: WorkflowRunIdOptional | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("RespondActivityTaskCanceled")
    def respond_activity_task_canceled(
        self, context: RequestContext, task_token: TaskToken, details: Data | None = None, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("RespondActivityTaskCompleted")
    def respond_activity_task_completed(
        self, context: RequestContext, task_token: TaskToken, result: Data | None = None, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("RespondActivityTaskFailed")
    def respond_activity_task_failed(
        self,
        context: RequestContext,
        task_token: TaskToken,
        reason: FailureReason | None = None,
        details: Data | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("RespondDecisionTaskCompleted")
    def respond_decision_task_completed(
        self,
        context: RequestContext,
        task_token: TaskToken,
        decisions: DecisionList | None = None,
        execution_context: Data | None = None,
        task_list: TaskList | None = None,
        task_list_schedule_to_start_timeout: DurationInSecondsOptional | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("SignalWorkflowExecution")
    def signal_workflow_execution(
        self,
        context: RequestContext,
        domain: DomainName,
        workflow_id: WorkflowId,
        signal_name: SignalName,
        run_id: WorkflowRunIdOptional | None = None,
        input: Data | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("StartWorkflowExecution")
    def start_workflow_execution(
        self,
        context: RequestContext,
        domain: DomainName,
        workflow_id: WorkflowId,
        workflow_type: WorkflowType,
        task_list: TaskList | None = None,
        task_priority: TaskPriority | None = None,
        input: Data | None = None,
        execution_start_to_close_timeout: DurationInSecondsOptional | None = None,
        tag_list: TagList | None = None,
        task_start_to_close_timeout: DurationInSecondsOptional | None = None,
        child_policy: ChildPolicy | None = None,
        lambda_role: Arn | None = None,
        **kwargs,
    ) -> Run:
        raise NotImplementedError

    @handler("TagResource")
    def tag_resource(
        self, context: RequestContext, resource_arn: Arn, tags: ResourceTagList, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("TerminateWorkflowExecution")
    def terminate_workflow_execution(
        self,
        context: RequestContext,
        domain: DomainName,
        workflow_id: WorkflowId,
        run_id: WorkflowRunIdOptional | None = None,
        reason: TerminateReason | None = None,
        details: Data | None = None,
        child_policy: ChildPolicy | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("UndeprecateActivityType")
    def undeprecate_activity_type(
        self, context: RequestContext, domain: DomainName, activity_type: ActivityType, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("UndeprecateDomain")
    def undeprecate_domain(self, context: RequestContext, name: DomainName, **kwargs) -> None:
        raise NotImplementedError

    @handler("UndeprecateWorkflowType")
    def undeprecate_workflow_type(
        self, context: RequestContext, domain: DomainName, workflow_type: WorkflowType, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("UntagResource")
    def untag_resource(
        self, context: RequestContext, resource_arn: Arn, tag_keys: ResourceTagKeyList, **kwargs
    ) -> None:
        raise NotImplementedError
