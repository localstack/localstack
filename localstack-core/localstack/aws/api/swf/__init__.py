from datetime import datetime
from typing import List, Optional, TypedDict

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


class ActivityTaskTimeoutType(str):
    START_TO_CLOSE = "START_TO_CLOSE"
    SCHEDULE_TO_START = "SCHEDULE_TO_START"
    SCHEDULE_TO_CLOSE = "SCHEDULE_TO_CLOSE"
    HEARTBEAT = "HEARTBEAT"


class CancelTimerFailedCause(str):
    TIMER_ID_UNKNOWN = "TIMER_ID_UNKNOWN"
    OPERATION_NOT_PERMITTED = "OPERATION_NOT_PERMITTED"


class CancelWorkflowExecutionFailedCause(str):
    UNHANDLED_DECISION = "UNHANDLED_DECISION"
    OPERATION_NOT_PERMITTED = "OPERATION_NOT_PERMITTED"


class ChildPolicy(str):
    TERMINATE = "TERMINATE"
    REQUEST_CANCEL = "REQUEST_CANCEL"
    ABANDON = "ABANDON"


class CloseStatus(str):
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELED = "CANCELED"
    TERMINATED = "TERMINATED"
    CONTINUED_AS_NEW = "CONTINUED_AS_NEW"
    TIMED_OUT = "TIMED_OUT"


class CompleteWorkflowExecutionFailedCause(str):
    UNHANDLED_DECISION = "UNHANDLED_DECISION"
    OPERATION_NOT_PERMITTED = "OPERATION_NOT_PERMITTED"


class ContinueAsNewWorkflowExecutionFailedCause(str):
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


class DecisionTaskTimeoutType(str):
    START_TO_CLOSE = "START_TO_CLOSE"
    SCHEDULE_TO_START = "SCHEDULE_TO_START"


class DecisionType(str):
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


class EventType(str):
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


class ExecutionStatus(str):
    OPEN = "OPEN"
    CLOSED = "CLOSED"


class FailWorkflowExecutionFailedCause(str):
    UNHANDLED_DECISION = "UNHANDLED_DECISION"
    OPERATION_NOT_PERMITTED = "OPERATION_NOT_PERMITTED"


class LambdaFunctionTimeoutType(str):
    START_TO_CLOSE = "START_TO_CLOSE"


class RecordMarkerFailedCause(str):
    OPERATION_NOT_PERMITTED = "OPERATION_NOT_PERMITTED"


class RegistrationStatus(str):
    REGISTERED = "REGISTERED"
    DEPRECATED = "DEPRECATED"


class RequestCancelActivityTaskFailedCause(str):
    ACTIVITY_ID_UNKNOWN = "ACTIVITY_ID_UNKNOWN"
    OPERATION_NOT_PERMITTED = "OPERATION_NOT_PERMITTED"


class RequestCancelExternalWorkflowExecutionFailedCause(str):
    UNKNOWN_EXTERNAL_WORKFLOW_EXECUTION = "UNKNOWN_EXTERNAL_WORKFLOW_EXECUTION"
    REQUEST_CANCEL_EXTERNAL_WORKFLOW_EXECUTION_RATE_EXCEEDED = (
        "REQUEST_CANCEL_EXTERNAL_WORKFLOW_EXECUTION_RATE_EXCEEDED"
    )
    OPERATION_NOT_PERMITTED = "OPERATION_NOT_PERMITTED"


class ScheduleActivityTaskFailedCause(str):
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


class ScheduleLambdaFunctionFailedCause(str):
    ID_ALREADY_IN_USE = "ID_ALREADY_IN_USE"
    OPEN_LAMBDA_FUNCTIONS_LIMIT_EXCEEDED = "OPEN_LAMBDA_FUNCTIONS_LIMIT_EXCEEDED"
    LAMBDA_FUNCTION_CREATION_RATE_EXCEEDED = "LAMBDA_FUNCTION_CREATION_RATE_EXCEEDED"
    LAMBDA_SERVICE_NOT_AVAILABLE_IN_REGION = "LAMBDA_SERVICE_NOT_AVAILABLE_IN_REGION"


class SignalExternalWorkflowExecutionFailedCause(str):
    UNKNOWN_EXTERNAL_WORKFLOW_EXECUTION = "UNKNOWN_EXTERNAL_WORKFLOW_EXECUTION"
    SIGNAL_EXTERNAL_WORKFLOW_EXECUTION_RATE_EXCEEDED = (
        "SIGNAL_EXTERNAL_WORKFLOW_EXECUTION_RATE_EXCEEDED"
    )
    OPERATION_NOT_PERMITTED = "OPERATION_NOT_PERMITTED"


class StartChildWorkflowExecutionFailedCause(str):
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


class StartLambdaFunctionFailedCause(str):
    ASSUME_ROLE_FAILED = "ASSUME_ROLE_FAILED"


class StartTimerFailedCause(str):
    TIMER_ID_ALREADY_IN_USE = "TIMER_ID_ALREADY_IN_USE"
    OPEN_TIMERS_LIMIT_EXCEEDED = "OPEN_TIMERS_LIMIT_EXCEEDED"
    TIMER_CREATION_RATE_EXCEEDED = "TIMER_CREATION_RATE_EXCEEDED"
    OPERATION_NOT_PERMITTED = "OPERATION_NOT_PERMITTED"


class WorkflowExecutionCancelRequestedCause(str):
    CHILD_POLICY_APPLIED = "CHILD_POLICY_APPLIED"


class WorkflowExecutionTerminatedCause(str):
    CHILD_POLICY_APPLIED = "CHILD_POLICY_APPLIED"
    EVENT_LIMIT_EXCEEDED = "EVENT_LIMIT_EXCEEDED"
    OPERATOR_INITIATED = "OPERATOR_INITIATED"


class WorkflowExecutionTimeoutType(str):
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
    input: Optional[Data]


class ActivityTaskCancelRequestedEventAttributes(TypedDict, total=False):
    decisionTaskCompletedEventId: EventId
    activityId: ActivityId


class ActivityTaskCanceledEventAttributes(TypedDict, total=False):
    details: Optional[Data]
    scheduledEventId: EventId
    startedEventId: EventId
    latestCancelRequestedEventId: Optional[EventId]


class ActivityTaskCompletedEventAttributes(TypedDict, total=False):
    result: Optional[Data]
    scheduledEventId: EventId
    startedEventId: EventId


class ActivityTaskFailedEventAttributes(TypedDict, total=False):
    reason: Optional[FailureReason]
    details: Optional[Data]
    scheduledEventId: EventId
    startedEventId: EventId


class TaskList(TypedDict, total=False):
    name: Name


class ActivityTaskScheduledEventAttributes(TypedDict, total=False):
    activityType: ActivityType
    activityId: ActivityId
    input: Optional[Data]
    control: Optional[Data]
    scheduleToStartTimeout: Optional[DurationInSecondsOptional]
    scheduleToCloseTimeout: Optional[DurationInSecondsOptional]
    startToCloseTimeout: Optional[DurationInSecondsOptional]
    taskList: TaskList
    taskPriority: Optional[TaskPriority]
    decisionTaskCompletedEventId: EventId
    heartbeatTimeout: Optional[DurationInSecondsOptional]


class ActivityTaskStartedEventAttributes(TypedDict, total=False):
    identity: Optional[Identity]
    scheduledEventId: EventId


class ActivityTaskStatus(TypedDict, total=False):
    cancelRequested: Canceled


class ActivityTaskTimedOutEventAttributes(TypedDict, total=False):
    timeoutType: ActivityTaskTimeoutType
    scheduledEventId: EventId
    startedEventId: EventId
    details: Optional[LimitedData]


class ActivityTypeConfiguration(TypedDict, total=False):
    defaultTaskStartToCloseTimeout: Optional[DurationInSecondsOptional]
    defaultTaskHeartbeatTimeout: Optional[DurationInSecondsOptional]
    defaultTaskList: Optional[TaskList]
    defaultTaskPriority: Optional[TaskPriority]
    defaultTaskScheduleToStartTimeout: Optional[DurationInSecondsOptional]
    defaultTaskScheduleToCloseTimeout: Optional[DurationInSecondsOptional]


Timestamp = datetime


class ActivityTypeInfo(TypedDict, total=False):
    activityType: ActivityType
    status: RegistrationStatus
    description: Optional[Description]
    creationDate: Timestamp
    deprecationDate: Optional[Timestamp]


class ActivityTypeDetail(TypedDict, total=False):
    typeInfo: ActivityTypeInfo
    configuration: ActivityTypeConfiguration


ActivityTypeInfoList = List[ActivityTypeInfo]


class ActivityTypeInfos(TypedDict, total=False):
    typeInfos: ActivityTypeInfoList
    nextPageToken: Optional[PageToken]


class CancelTimerDecisionAttributes(TypedDict, total=False):
    timerId: TimerId


class CancelTimerFailedEventAttributes(TypedDict, total=False):
    timerId: TimerId
    cause: CancelTimerFailedCause
    decisionTaskCompletedEventId: EventId


class CancelWorkflowExecutionDecisionAttributes(TypedDict, total=False):
    details: Optional[Data]


class CancelWorkflowExecutionFailedEventAttributes(TypedDict, total=False):
    cause: CancelWorkflowExecutionFailedCause
    decisionTaskCompletedEventId: EventId


class WorkflowType(TypedDict, total=False):
    name: Name
    version: Version


class ChildWorkflowExecutionCanceledEventAttributes(TypedDict, total=False):
    workflowExecution: WorkflowExecution
    workflowType: WorkflowType
    details: Optional[Data]
    initiatedEventId: EventId
    startedEventId: EventId


class ChildWorkflowExecutionCompletedEventAttributes(TypedDict, total=False):
    workflowExecution: WorkflowExecution
    workflowType: WorkflowType
    result: Optional[Data]
    initiatedEventId: EventId
    startedEventId: EventId


class ChildWorkflowExecutionFailedEventAttributes(TypedDict, total=False):
    workflowExecution: WorkflowExecution
    workflowType: WorkflowType
    reason: Optional[FailureReason]
    details: Optional[Data]
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
    result: Optional[Data]


class CompleteWorkflowExecutionFailedEventAttributes(TypedDict, total=False):
    cause: CompleteWorkflowExecutionFailedCause
    decisionTaskCompletedEventId: EventId


TagList = List[Tag]


class ContinueAsNewWorkflowExecutionDecisionAttributes(TypedDict, total=False):
    input: Optional[Data]
    executionStartToCloseTimeout: Optional[DurationInSecondsOptional]
    taskList: Optional[TaskList]
    taskPriority: Optional[TaskPriority]
    taskStartToCloseTimeout: Optional[DurationInSecondsOptional]
    childPolicy: Optional[ChildPolicy]
    tagList: Optional[TagList]
    workflowTypeVersion: Optional[Version]
    lambdaRole: Optional[Arn]


class ContinueAsNewWorkflowExecutionFailedEventAttributes(TypedDict, total=False):
    cause: ContinueAsNewWorkflowExecutionFailedCause
    decisionTaskCompletedEventId: EventId


class TagFilter(TypedDict, total=False):
    tag: Tag


class WorkflowTypeFilter(TypedDict, total=False):
    name: Name
    version: Optional[VersionOptional]


class WorkflowExecutionFilter(TypedDict, total=False):
    workflowId: WorkflowId


class ExecutionTimeFilter(TypedDict, total=False):
    oldestDate: Timestamp
    latestDate: Optional[Timestamp]


class CountClosedWorkflowExecutionsInput(ServiceRequest):
    domain: DomainName
    startTimeFilter: Optional[ExecutionTimeFilter]
    closeTimeFilter: Optional[ExecutionTimeFilter]
    executionFilter: Optional[WorkflowExecutionFilter]
    typeFilter: Optional[WorkflowTypeFilter]
    tagFilter: Optional[TagFilter]
    closeStatusFilter: Optional[CloseStatusFilter]


class CountOpenWorkflowExecutionsInput(ServiceRequest):
    domain: DomainName
    startTimeFilter: ExecutionTimeFilter
    typeFilter: Optional[WorkflowTypeFilter]
    tagFilter: Optional[TagFilter]
    executionFilter: Optional[WorkflowExecutionFilter]


class CountPendingActivityTasksInput(ServiceRequest):
    domain: DomainName
    taskList: TaskList


class CountPendingDecisionTasksInput(ServiceRequest):
    domain: DomainName
    taskList: TaskList


class ScheduleLambdaFunctionDecisionAttributes(TypedDict, total=False):
    id: FunctionId
    name: FunctionName
    control: Optional[Data]
    input: Optional[FunctionInput]
    startToCloseTimeout: Optional[DurationInSecondsOptional]


class StartChildWorkflowExecutionDecisionAttributes(TypedDict, total=False):
    workflowType: WorkflowType
    workflowId: WorkflowId
    control: Optional[Data]
    input: Optional[Data]
    executionStartToCloseTimeout: Optional[DurationInSecondsOptional]
    taskList: Optional[TaskList]
    taskPriority: Optional[TaskPriority]
    taskStartToCloseTimeout: Optional[DurationInSecondsOptional]
    childPolicy: Optional[ChildPolicy]
    tagList: Optional[TagList]
    lambdaRole: Optional[Arn]


class RequestCancelExternalWorkflowExecutionDecisionAttributes(TypedDict, total=False):
    workflowId: WorkflowId
    runId: Optional[WorkflowRunIdOptional]
    control: Optional[Data]


class SignalExternalWorkflowExecutionDecisionAttributes(TypedDict, total=False):
    workflowId: WorkflowId
    runId: Optional[WorkflowRunIdOptional]
    signalName: SignalName
    input: Optional[Data]
    control: Optional[Data]


class StartTimerDecisionAttributes(TypedDict, total=False):
    timerId: TimerId
    control: Optional[Data]
    startToFireTimeout: DurationInSeconds


class RecordMarkerDecisionAttributes(TypedDict, total=False):
    markerName: MarkerName
    details: Optional[Data]


class FailWorkflowExecutionDecisionAttributes(TypedDict, total=False):
    reason: Optional[FailureReason]
    details: Optional[Data]


class RequestCancelActivityTaskDecisionAttributes(TypedDict, total=False):
    activityId: ActivityId


class ScheduleActivityTaskDecisionAttributes(TypedDict, total=False):
    activityType: ActivityType
    activityId: ActivityId
    control: Optional[Data]
    input: Optional[Data]
    scheduleToCloseTimeout: Optional[DurationInSecondsOptional]
    taskList: Optional[TaskList]
    taskPriority: Optional[TaskPriority]
    scheduleToStartTimeout: Optional[DurationInSecondsOptional]
    startToCloseTimeout: Optional[DurationInSecondsOptional]
    heartbeatTimeout: Optional[DurationInSecondsOptional]


class Decision(TypedDict, total=False):
    decisionType: DecisionType
    scheduleActivityTaskDecisionAttributes: Optional[ScheduleActivityTaskDecisionAttributes]
    requestCancelActivityTaskDecisionAttributes: Optional[
        RequestCancelActivityTaskDecisionAttributes
    ]
    completeWorkflowExecutionDecisionAttributes: Optional[
        CompleteWorkflowExecutionDecisionAttributes
    ]
    failWorkflowExecutionDecisionAttributes: Optional[FailWorkflowExecutionDecisionAttributes]
    cancelWorkflowExecutionDecisionAttributes: Optional[CancelWorkflowExecutionDecisionAttributes]
    continueAsNewWorkflowExecutionDecisionAttributes: Optional[
        ContinueAsNewWorkflowExecutionDecisionAttributes
    ]
    recordMarkerDecisionAttributes: Optional[RecordMarkerDecisionAttributes]
    startTimerDecisionAttributes: Optional[StartTimerDecisionAttributes]
    cancelTimerDecisionAttributes: Optional[CancelTimerDecisionAttributes]
    signalExternalWorkflowExecutionDecisionAttributes: Optional[
        SignalExternalWorkflowExecutionDecisionAttributes
    ]
    requestCancelExternalWorkflowExecutionDecisionAttributes: Optional[
        RequestCancelExternalWorkflowExecutionDecisionAttributes
    ]
    startChildWorkflowExecutionDecisionAttributes: Optional[
        StartChildWorkflowExecutionDecisionAttributes
    ]
    scheduleLambdaFunctionDecisionAttributes: Optional[ScheduleLambdaFunctionDecisionAttributes]


DecisionList = List[Decision]


class StartLambdaFunctionFailedEventAttributes(TypedDict, total=False):
    scheduledEventId: Optional[EventId]
    cause: Optional[StartLambdaFunctionFailedCause]
    message: Optional[CauseMessage]


class ScheduleLambdaFunctionFailedEventAttributes(TypedDict, total=False):
    id: FunctionId
    name: FunctionName
    cause: ScheduleLambdaFunctionFailedCause
    decisionTaskCompletedEventId: EventId


class LambdaFunctionTimedOutEventAttributes(TypedDict, total=False):
    scheduledEventId: EventId
    startedEventId: EventId
    timeoutType: Optional[LambdaFunctionTimeoutType]


class LambdaFunctionFailedEventAttributes(TypedDict, total=False):
    scheduledEventId: EventId
    startedEventId: EventId
    reason: Optional[FailureReason]
    details: Optional[Data]


class LambdaFunctionCompletedEventAttributes(TypedDict, total=False):
    scheduledEventId: EventId
    startedEventId: EventId
    result: Optional[Data]


class LambdaFunctionStartedEventAttributes(TypedDict, total=False):
    scheduledEventId: EventId


class LambdaFunctionScheduledEventAttributes(TypedDict, total=False):
    id: FunctionId
    name: FunctionName
    control: Optional[Data]
    input: Optional[FunctionInput]
    startToCloseTimeout: Optional[DurationInSecondsOptional]
    decisionTaskCompletedEventId: EventId


class StartChildWorkflowExecutionFailedEventAttributes(TypedDict, total=False):
    workflowType: WorkflowType
    cause: StartChildWorkflowExecutionFailedCause
    workflowId: WorkflowId
    initiatedEventId: EventId
    decisionTaskCompletedEventId: EventId
    control: Optional[Data]


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
    runId: Optional[WorkflowRunIdOptional]
    cause: RequestCancelExternalWorkflowExecutionFailedCause
    initiatedEventId: EventId
    decisionTaskCompletedEventId: EventId
    control: Optional[Data]


class RequestCancelExternalWorkflowExecutionInitiatedEventAttributes(TypedDict, total=False):
    workflowId: WorkflowId
    runId: Optional[WorkflowRunIdOptional]
    decisionTaskCompletedEventId: EventId
    control: Optional[Data]


class ExternalWorkflowExecutionCancelRequestedEventAttributes(TypedDict, total=False):
    workflowExecution: WorkflowExecution
    initiatedEventId: EventId


class SignalExternalWorkflowExecutionFailedEventAttributes(TypedDict, total=False):
    workflowId: WorkflowId
    runId: Optional[WorkflowRunIdOptional]
    cause: SignalExternalWorkflowExecutionFailedCause
    initiatedEventId: EventId
    decisionTaskCompletedEventId: EventId
    control: Optional[Data]


class ExternalWorkflowExecutionSignaledEventAttributes(TypedDict, total=False):
    workflowExecution: WorkflowExecution
    initiatedEventId: EventId


class SignalExternalWorkflowExecutionInitiatedEventAttributes(TypedDict, total=False):
    workflowId: WorkflowId
    runId: Optional[WorkflowRunIdOptional]
    signalName: SignalName
    input: Optional[Data]
    decisionTaskCompletedEventId: EventId
    control: Optional[Data]


class StartChildWorkflowExecutionInitiatedEventAttributes(TypedDict, total=False):
    workflowId: WorkflowId
    workflowType: WorkflowType
    control: Optional[Data]
    input: Optional[Data]
    executionStartToCloseTimeout: Optional[DurationInSecondsOptional]
    taskList: TaskList
    taskPriority: Optional[TaskPriority]
    decisionTaskCompletedEventId: EventId
    childPolicy: ChildPolicy
    taskStartToCloseTimeout: Optional[DurationInSecondsOptional]
    tagList: Optional[TagList]
    lambdaRole: Optional[Arn]


class TimerCanceledEventAttributes(TypedDict, total=False):
    timerId: TimerId
    startedEventId: EventId
    decisionTaskCompletedEventId: EventId


class TimerFiredEventAttributes(TypedDict, total=False):
    timerId: TimerId
    startedEventId: EventId


class TimerStartedEventAttributes(TypedDict, total=False):
    timerId: TimerId
    control: Optional[Data]
    startToFireTimeout: DurationInSeconds
    decisionTaskCompletedEventId: EventId


class RecordMarkerFailedEventAttributes(TypedDict, total=False):
    markerName: MarkerName
    cause: RecordMarkerFailedCause
    decisionTaskCompletedEventId: EventId


class MarkerRecordedEventAttributes(TypedDict, total=False):
    markerName: MarkerName
    details: Optional[Data]
    decisionTaskCompletedEventId: EventId


class WorkflowExecutionSignaledEventAttributes(TypedDict, total=False):
    signalName: SignalName
    input: Optional[Data]
    externalWorkflowExecution: Optional[WorkflowExecution]
    externalInitiatedEventId: Optional[EventId]


class DecisionTaskTimedOutEventAttributes(TypedDict, total=False):
    timeoutType: DecisionTaskTimeoutType
    scheduledEventId: EventId
    startedEventId: EventId


class DecisionTaskCompletedEventAttributes(TypedDict, total=False):
    executionContext: Optional[Data]
    scheduledEventId: EventId
    startedEventId: EventId
    taskList: Optional[TaskList]
    taskListScheduleToStartTimeout: Optional[DurationInSecondsOptional]


class DecisionTaskStartedEventAttributes(TypedDict, total=False):
    identity: Optional[Identity]
    scheduledEventId: EventId


class DecisionTaskScheduledEventAttributes(TypedDict, total=False):
    taskList: TaskList
    taskPriority: Optional[TaskPriority]
    startToCloseTimeout: Optional[DurationInSecondsOptional]
    scheduleToStartTimeout: Optional[DurationInSecondsOptional]


class WorkflowExecutionCancelRequestedEventAttributes(TypedDict, total=False):
    externalWorkflowExecution: Optional[WorkflowExecution]
    externalInitiatedEventId: Optional[EventId]
    cause: Optional[WorkflowExecutionCancelRequestedCause]


class WorkflowExecutionTerminatedEventAttributes(TypedDict, total=False):
    reason: Optional[TerminateReason]
    details: Optional[Data]
    childPolicy: ChildPolicy
    cause: Optional[WorkflowExecutionTerminatedCause]


class WorkflowExecutionContinuedAsNewEventAttributes(TypedDict, total=False):
    input: Optional[Data]
    decisionTaskCompletedEventId: EventId
    newExecutionRunId: WorkflowRunId
    executionStartToCloseTimeout: Optional[DurationInSecondsOptional]
    taskList: TaskList
    taskPriority: Optional[TaskPriority]
    taskStartToCloseTimeout: Optional[DurationInSecondsOptional]
    childPolicy: ChildPolicy
    tagList: Optional[TagList]
    workflowType: WorkflowType
    lambdaRole: Optional[Arn]


class WorkflowExecutionCanceledEventAttributes(TypedDict, total=False):
    details: Optional[Data]
    decisionTaskCompletedEventId: EventId


class WorkflowExecutionTimedOutEventAttributes(TypedDict, total=False):
    timeoutType: WorkflowExecutionTimeoutType
    childPolicy: ChildPolicy


class FailWorkflowExecutionFailedEventAttributes(TypedDict, total=False):
    cause: FailWorkflowExecutionFailedCause
    decisionTaskCompletedEventId: EventId


class WorkflowExecutionFailedEventAttributes(TypedDict, total=False):
    reason: Optional[FailureReason]
    details: Optional[Data]
    decisionTaskCompletedEventId: EventId


class WorkflowExecutionCompletedEventAttributes(TypedDict, total=False):
    result: Optional[Data]
    decisionTaskCompletedEventId: EventId


class WorkflowExecutionStartedEventAttributes(TypedDict, total=False):
    input: Optional[Data]
    executionStartToCloseTimeout: Optional[DurationInSecondsOptional]
    taskStartToCloseTimeout: Optional[DurationInSecondsOptional]
    childPolicy: ChildPolicy
    taskList: TaskList
    taskPriority: Optional[TaskPriority]
    workflowType: WorkflowType
    tagList: Optional[TagList]
    continuedExecutionRunId: Optional[WorkflowRunIdOptional]
    parentWorkflowExecution: Optional[WorkflowExecution]
    parentInitiatedEventId: Optional[EventId]
    lambdaRole: Optional[Arn]


class HistoryEvent(TypedDict, total=False):
    eventTimestamp: Timestamp
    eventType: EventType
    eventId: EventId
    workflowExecutionStartedEventAttributes: Optional[WorkflowExecutionStartedEventAttributes]
    workflowExecutionCompletedEventAttributes: Optional[WorkflowExecutionCompletedEventAttributes]
    completeWorkflowExecutionFailedEventAttributes: Optional[
        CompleteWorkflowExecutionFailedEventAttributes
    ]
    workflowExecutionFailedEventAttributes: Optional[WorkflowExecutionFailedEventAttributes]
    failWorkflowExecutionFailedEventAttributes: Optional[FailWorkflowExecutionFailedEventAttributes]
    workflowExecutionTimedOutEventAttributes: Optional[WorkflowExecutionTimedOutEventAttributes]
    workflowExecutionCanceledEventAttributes: Optional[WorkflowExecutionCanceledEventAttributes]
    cancelWorkflowExecutionFailedEventAttributes: Optional[
        CancelWorkflowExecutionFailedEventAttributes
    ]
    workflowExecutionContinuedAsNewEventAttributes: Optional[
        WorkflowExecutionContinuedAsNewEventAttributes
    ]
    continueAsNewWorkflowExecutionFailedEventAttributes: Optional[
        ContinueAsNewWorkflowExecutionFailedEventAttributes
    ]
    workflowExecutionTerminatedEventAttributes: Optional[WorkflowExecutionTerminatedEventAttributes]
    workflowExecutionCancelRequestedEventAttributes: Optional[
        WorkflowExecutionCancelRequestedEventAttributes
    ]
    decisionTaskScheduledEventAttributes: Optional[DecisionTaskScheduledEventAttributes]
    decisionTaskStartedEventAttributes: Optional[DecisionTaskStartedEventAttributes]
    decisionTaskCompletedEventAttributes: Optional[DecisionTaskCompletedEventAttributes]
    decisionTaskTimedOutEventAttributes: Optional[DecisionTaskTimedOutEventAttributes]
    activityTaskScheduledEventAttributes: Optional[ActivityTaskScheduledEventAttributes]
    activityTaskStartedEventAttributes: Optional[ActivityTaskStartedEventAttributes]
    activityTaskCompletedEventAttributes: Optional[ActivityTaskCompletedEventAttributes]
    activityTaskFailedEventAttributes: Optional[ActivityTaskFailedEventAttributes]
    activityTaskTimedOutEventAttributes: Optional[ActivityTaskTimedOutEventAttributes]
    activityTaskCanceledEventAttributes: Optional[ActivityTaskCanceledEventAttributes]
    activityTaskCancelRequestedEventAttributes: Optional[ActivityTaskCancelRequestedEventAttributes]
    workflowExecutionSignaledEventAttributes: Optional[WorkflowExecutionSignaledEventAttributes]
    markerRecordedEventAttributes: Optional[MarkerRecordedEventAttributes]
    recordMarkerFailedEventAttributes: Optional[RecordMarkerFailedEventAttributes]
    timerStartedEventAttributes: Optional[TimerStartedEventAttributes]
    timerFiredEventAttributes: Optional[TimerFiredEventAttributes]
    timerCanceledEventAttributes: Optional[TimerCanceledEventAttributes]
    startChildWorkflowExecutionInitiatedEventAttributes: Optional[
        StartChildWorkflowExecutionInitiatedEventAttributes
    ]
    childWorkflowExecutionStartedEventAttributes: Optional[
        ChildWorkflowExecutionStartedEventAttributes
    ]
    childWorkflowExecutionCompletedEventAttributes: Optional[
        ChildWorkflowExecutionCompletedEventAttributes
    ]
    childWorkflowExecutionFailedEventAttributes: Optional[
        ChildWorkflowExecutionFailedEventAttributes
    ]
    childWorkflowExecutionTimedOutEventAttributes: Optional[
        ChildWorkflowExecutionTimedOutEventAttributes
    ]
    childWorkflowExecutionCanceledEventAttributes: Optional[
        ChildWorkflowExecutionCanceledEventAttributes
    ]
    childWorkflowExecutionTerminatedEventAttributes: Optional[
        ChildWorkflowExecutionTerminatedEventAttributes
    ]
    signalExternalWorkflowExecutionInitiatedEventAttributes: Optional[
        SignalExternalWorkflowExecutionInitiatedEventAttributes
    ]
    externalWorkflowExecutionSignaledEventAttributes: Optional[
        ExternalWorkflowExecutionSignaledEventAttributes
    ]
    signalExternalWorkflowExecutionFailedEventAttributes: Optional[
        SignalExternalWorkflowExecutionFailedEventAttributes
    ]
    externalWorkflowExecutionCancelRequestedEventAttributes: Optional[
        ExternalWorkflowExecutionCancelRequestedEventAttributes
    ]
    requestCancelExternalWorkflowExecutionInitiatedEventAttributes: Optional[
        RequestCancelExternalWorkflowExecutionInitiatedEventAttributes
    ]
    requestCancelExternalWorkflowExecutionFailedEventAttributes: Optional[
        RequestCancelExternalWorkflowExecutionFailedEventAttributes
    ]
    scheduleActivityTaskFailedEventAttributes: Optional[ScheduleActivityTaskFailedEventAttributes]
    requestCancelActivityTaskFailedEventAttributes: Optional[
        RequestCancelActivityTaskFailedEventAttributes
    ]
    startTimerFailedEventAttributes: Optional[StartTimerFailedEventAttributes]
    cancelTimerFailedEventAttributes: Optional[CancelTimerFailedEventAttributes]
    startChildWorkflowExecutionFailedEventAttributes: Optional[
        StartChildWorkflowExecutionFailedEventAttributes
    ]
    lambdaFunctionScheduledEventAttributes: Optional[LambdaFunctionScheduledEventAttributes]
    lambdaFunctionStartedEventAttributes: Optional[LambdaFunctionStartedEventAttributes]
    lambdaFunctionCompletedEventAttributes: Optional[LambdaFunctionCompletedEventAttributes]
    lambdaFunctionFailedEventAttributes: Optional[LambdaFunctionFailedEventAttributes]
    lambdaFunctionTimedOutEventAttributes: Optional[LambdaFunctionTimedOutEventAttributes]
    scheduleLambdaFunctionFailedEventAttributes: Optional[
        ScheduleLambdaFunctionFailedEventAttributes
    ]
    startLambdaFunctionFailedEventAttributes: Optional[StartLambdaFunctionFailedEventAttributes]


HistoryEventList = List[HistoryEvent]


class DecisionTask(TypedDict, total=False):
    taskToken: TaskToken
    startedEventId: EventId
    workflowExecution: WorkflowExecution
    workflowType: WorkflowType
    events: HistoryEventList
    nextPageToken: Optional[PageToken]
    previousStartedEventId: Optional[EventId]


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
    description: Optional[Description]
    arn: Optional[Arn]


class DomainDetail(TypedDict, total=False):
    domainInfo: DomainInfo
    configuration: DomainConfiguration


DomainInfoList = List[DomainInfo]


class DomainInfos(TypedDict, total=False):
    domainInfos: DomainInfoList
    nextPageToken: Optional[PageToken]


class GetWorkflowExecutionHistoryInput(ServiceRequest):
    domain: DomainName
    execution: WorkflowExecution
    nextPageToken: Optional[PageToken]
    maximumPageSize: Optional[PageSize]
    reverseOrder: Optional[ReverseOrder]


class History(TypedDict, total=False):
    events: HistoryEventList
    nextPageToken: Optional[PageToken]


class ListActivityTypesInput(ServiceRequest):
    domain: DomainName
    name: Optional[Name]
    registrationStatus: RegistrationStatus
    nextPageToken: Optional[PageToken]
    maximumPageSize: Optional[PageSize]
    reverseOrder: Optional[ReverseOrder]


class ListClosedWorkflowExecutionsInput(ServiceRequest):
    domain: DomainName
    startTimeFilter: Optional[ExecutionTimeFilter]
    closeTimeFilter: Optional[ExecutionTimeFilter]
    executionFilter: Optional[WorkflowExecutionFilter]
    closeStatusFilter: Optional[CloseStatusFilter]
    typeFilter: Optional[WorkflowTypeFilter]
    tagFilter: Optional[TagFilter]
    nextPageToken: Optional[PageToken]
    maximumPageSize: Optional[PageSize]
    reverseOrder: Optional[ReverseOrder]


class ListDomainsInput(ServiceRequest):
    nextPageToken: Optional[PageToken]
    registrationStatus: RegistrationStatus
    maximumPageSize: Optional[PageSize]
    reverseOrder: Optional[ReverseOrder]


class ListOpenWorkflowExecutionsInput(ServiceRequest):
    domain: DomainName
    startTimeFilter: ExecutionTimeFilter
    typeFilter: Optional[WorkflowTypeFilter]
    tagFilter: Optional[TagFilter]
    nextPageToken: Optional[PageToken]
    maximumPageSize: Optional[PageSize]
    reverseOrder: Optional[ReverseOrder]
    executionFilter: Optional[WorkflowExecutionFilter]


class ListTagsForResourceInput(ServiceRequest):
    resourceArn: Arn


class ResourceTag(TypedDict, total=False):
    key: ResourceTagKey
    value: Optional[ResourceTagValue]


ResourceTagList = List[ResourceTag]


class ListTagsForResourceOutput(TypedDict, total=False):
    tags: Optional[ResourceTagList]


class ListWorkflowTypesInput(ServiceRequest):
    domain: DomainName
    name: Optional[Name]
    registrationStatus: RegistrationStatus
    nextPageToken: Optional[PageToken]
    maximumPageSize: Optional[PageSize]
    reverseOrder: Optional[ReverseOrder]


class PendingTaskCount(TypedDict, total=False):
    count: Count
    truncated: Optional[Truncated]


class PollForActivityTaskInput(ServiceRequest):
    domain: DomainName
    taskList: TaskList
    identity: Optional[Identity]


class PollForDecisionTaskInput(ServiceRequest):
    domain: DomainName
    taskList: TaskList
    identity: Optional[Identity]
    nextPageToken: Optional[PageToken]
    maximumPageSize: Optional[PageSize]
    reverseOrder: Optional[ReverseOrder]
    startAtPreviousStartedEvent: Optional[StartAtPreviousStartedEvent]


class RecordActivityTaskHeartbeatInput(ServiceRequest):
    taskToken: TaskToken
    details: Optional[LimitedData]


class RegisterActivityTypeInput(ServiceRequest):
    domain: DomainName
    name: Name
    version: Version
    description: Optional[Description]
    defaultTaskStartToCloseTimeout: Optional[DurationInSecondsOptional]
    defaultTaskHeartbeatTimeout: Optional[DurationInSecondsOptional]
    defaultTaskList: Optional[TaskList]
    defaultTaskPriority: Optional[TaskPriority]
    defaultTaskScheduleToStartTimeout: Optional[DurationInSecondsOptional]
    defaultTaskScheduleToCloseTimeout: Optional[DurationInSecondsOptional]


class RegisterDomainInput(ServiceRequest):
    name: DomainName
    description: Optional[Description]
    workflowExecutionRetentionPeriodInDays: DurationInDays
    tags: Optional[ResourceTagList]


class RegisterWorkflowTypeInput(ServiceRequest):
    domain: DomainName
    name: Name
    version: Version
    description: Optional[Description]
    defaultTaskStartToCloseTimeout: Optional[DurationInSecondsOptional]
    defaultExecutionStartToCloseTimeout: Optional[DurationInSecondsOptional]
    defaultTaskList: Optional[TaskList]
    defaultTaskPriority: Optional[TaskPriority]
    defaultChildPolicy: Optional[ChildPolicy]
    defaultLambdaRole: Optional[Arn]


class RequestCancelWorkflowExecutionInput(ServiceRequest):
    domain: DomainName
    workflowId: WorkflowId
    runId: Optional[WorkflowRunIdOptional]


ResourceTagKeyList = List[ResourceTagKey]


class RespondActivityTaskCanceledInput(ServiceRequest):
    taskToken: TaskToken
    details: Optional[Data]


class RespondActivityTaskCompletedInput(ServiceRequest):
    taskToken: TaskToken
    result: Optional[Data]


class RespondActivityTaskFailedInput(ServiceRequest):
    taskToken: TaskToken
    reason: Optional[FailureReason]
    details: Optional[Data]


class RespondDecisionTaskCompletedInput(ServiceRequest):
    taskToken: TaskToken
    decisions: Optional[DecisionList]
    executionContext: Optional[Data]
    taskList: Optional[TaskList]
    taskListScheduleToStartTimeout: Optional[DurationInSecondsOptional]


class Run(TypedDict, total=False):
    runId: Optional[WorkflowRunId]


class SignalWorkflowExecutionInput(ServiceRequest):
    domain: DomainName
    workflowId: WorkflowId
    runId: Optional[WorkflowRunIdOptional]
    signalName: SignalName
    input: Optional[Data]


class StartWorkflowExecutionInput(ServiceRequest):
    domain: DomainName
    workflowId: WorkflowId
    workflowType: WorkflowType
    taskList: Optional[TaskList]
    taskPriority: Optional[TaskPriority]
    input: Optional[Data]
    executionStartToCloseTimeout: Optional[DurationInSecondsOptional]
    tagList: Optional[TagList]
    taskStartToCloseTimeout: Optional[DurationInSecondsOptional]
    childPolicy: Optional[ChildPolicy]
    lambdaRole: Optional[Arn]


class TagResourceInput(ServiceRequest):
    resourceArn: Arn
    tags: ResourceTagList


class TerminateWorkflowExecutionInput(ServiceRequest):
    domain: DomainName
    workflowId: WorkflowId
    runId: Optional[WorkflowRunIdOptional]
    reason: Optional[TerminateReason]
    details: Optional[Data]
    childPolicy: Optional[ChildPolicy]


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
    taskPriority: Optional[TaskPriority]
    childPolicy: ChildPolicy
    lambdaRole: Optional[Arn]


class WorkflowExecutionCount(TypedDict, total=False):
    count: Count
    truncated: Optional[Truncated]


class WorkflowExecutionOpenCounts(TypedDict, total=False):
    openActivityTasks: Count
    openDecisionTasks: OpenDecisionTasksCount
    openTimers: Count
    openChildWorkflowExecutions: Count
    openLambdaFunctions: Optional[Count]


class WorkflowExecutionInfo(TypedDict, total=False):
    execution: WorkflowExecution
    workflowType: WorkflowType
    startTimestamp: Timestamp
    closeTimestamp: Optional[Timestamp]
    executionStatus: ExecutionStatus
    closeStatus: Optional[CloseStatus]
    parent: Optional[WorkflowExecution]
    tagList: Optional[TagList]
    cancelRequested: Optional[Canceled]


class WorkflowExecutionDetail(TypedDict, total=False):
    executionInfo: WorkflowExecutionInfo
    executionConfiguration: WorkflowExecutionConfiguration
    openCounts: WorkflowExecutionOpenCounts
    latestActivityTaskTimestamp: Optional[Timestamp]
    latestExecutionContext: Optional[Data]


WorkflowExecutionInfoList = List[WorkflowExecutionInfo]


class WorkflowExecutionInfos(TypedDict, total=False):
    executionInfos: WorkflowExecutionInfoList
    nextPageToken: Optional[PageToken]


class WorkflowTypeConfiguration(TypedDict, total=False):
    defaultTaskStartToCloseTimeout: Optional[DurationInSecondsOptional]
    defaultExecutionStartToCloseTimeout: Optional[DurationInSecondsOptional]
    defaultTaskList: Optional[TaskList]
    defaultTaskPriority: Optional[TaskPriority]
    defaultChildPolicy: Optional[ChildPolicy]
    defaultLambdaRole: Optional[Arn]


class WorkflowTypeInfo(TypedDict, total=False):
    workflowType: WorkflowType
    status: RegistrationStatus
    description: Optional[Description]
    creationDate: Timestamp
    deprecationDate: Optional[Timestamp]


class WorkflowTypeDetail(TypedDict, total=False):
    typeInfo: WorkflowTypeInfo
    configuration: WorkflowTypeConfiguration


WorkflowTypeInfoList = List[WorkflowTypeInfo]


class WorkflowTypeInfos(TypedDict, total=False):
    typeInfos: WorkflowTypeInfoList
    nextPageToken: Optional[PageToken]


class SwfApi:
    service = "swf"
    version = "2012-01-25"

    @handler("CountClosedWorkflowExecutions")
    def count_closed_workflow_executions(
        self,
        context: RequestContext,
        domain: DomainName,
        start_time_filter: ExecutionTimeFilter = None,
        close_time_filter: ExecutionTimeFilter = None,
        execution_filter: WorkflowExecutionFilter = None,
        type_filter: WorkflowTypeFilter = None,
        tag_filter: TagFilter = None,
        close_status_filter: CloseStatusFilter = None,
        **kwargs,
    ) -> WorkflowExecutionCount:
        raise NotImplementedError

    @handler("CountOpenWorkflowExecutions")
    def count_open_workflow_executions(
        self,
        context: RequestContext,
        domain: DomainName,
        start_time_filter: ExecutionTimeFilter,
        type_filter: WorkflowTypeFilter = None,
        tag_filter: TagFilter = None,
        execution_filter: WorkflowExecutionFilter = None,
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
        next_page_token: PageToken = None,
        maximum_page_size: PageSize = None,
        reverse_order: ReverseOrder = None,
        **kwargs,
    ) -> History:
        raise NotImplementedError

    @handler("ListActivityTypes")
    def list_activity_types(
        self,
        context: RequestContext,
        domain: DomainName,
        registration_status: RegistrationStatus,
        name: Name = None,
        next_page_token: PageToken = None,
        maximum_page_size: PageSize = None,
        reverse_order: ReverseOrder = None,
        **kwargs,
    ) -> ActivityTypeInfos:
        raise NotImplementedError

    @handler("ListClosedWorkflowExecutions")
    def list_closed_workflow_executions(
        self,
        context: RequestContext,
        domain: DomainName,
        start_time_filter: ExecutionTimeFilter = None,
        close_time_filter: ExecutionTimeFilter = None,
        execution_filter: WorkflowExecutionFilter = None,
        close_status_filter: CloseStatusFilter = None,
        type_filter: WorkflowTypeFilter = None,
        tag_filter: TagFilter = None,
        next_page_token: PageToken = None,
        maximum_page_size: PageSize = None,
        reverse_order: ReverseOrder = None,
        **kwargs,
    ) -> WorkflowExecutionInfos:
        raise NotImplementedError

    @handler("ListDomains")
    def list_domains(
        self,
        context: RequestContext,
        registration_status: RegistrationStatus,
        next_page_token: PageToken = None,
        maximum_page_size: PageSize = None,
        reverse_order: ReverseOrder = None,
        **kwargs,
    ) -> DomainInfos:
        raise NotImplementedError

    @handler("ListOpenWorkflowExecutions")
    def list_open_workflow_executions(
        self,
        context: RequestContext,
        domain: DomainName,
        start_time_filter: ExecutionTimeFilter,
        type_filter: WorkflowTypeFilter = None,
        tag_filter: TagFilter = None,
        next_page_token: PageToken = None,
        maximum_page_size: PageSize = None,
        reverse_order: ReverseOrder = None,
        execution_filter: WorkflowExecutionFilter = None,
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
        name: Name = None,
        next_page_token: PageToken = None,
        maximum_page_size: PageSize = None,
        reverse_order: ReverseOrder = None,
        **kwargs,
    ) -> WorkflowTypeInfos:
        raise NotImplementedError

    @handler("PollForActivityTask")
    def poll_for_activity_task(
        self,
        context: RequestContext,
        domain: DomainName,
        task_list: TaskList,
        identity: Identity = None,
        **kwargs,
    ) -> ActivityTask:
        raise NotImplementedError

    @handler("PollForDecisionTask")
    def poll_for_decision_task(
        self,
        context: RequestContext,
        domain: DomainName,
        task_list: TaskList,
        identity: Identity = None,
        next_page_token: PageToken = None,
        maximum_page_size: PageSize = None,
        reverse_order: ReverseOrder = None,
        start_at_previous_started_event: StartAtPreviousStartedEvent = None,
        **kwargs,
    ) -> DecisionTask:
        raise NotImplementedError

    @handler("RecordActivityTaskHeartbeat")
    def record_activity_task_heartbeat(
        self, context: RequestContext, task_token: TaskToken, details: LimitedData = None, **kwargs
    ) -> ActivityTaskStatus:
        raise NotImplementedError

    @handler("RegisterActivityType")
    def register_activity_type(
        self,
        context: RequestContext,
        domain: DomainName,
        name: Name,
        version: Version,
        description: Description = None,
        default_task_start_to_close_timeout: DurationInSecondsOptional = None,
        default_task_heartbeat_timeout: DurationInSecondsOptional = None,
        default_task_list: TaskList = None,
        default_task_priority: TaskPriority = None,
        default_task_schedule_to_start_timeout: DurationInSecondsOptional = None,
        default_task_schedule_to_close_timeout: DurationInSecondsOptional = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("RegisterDomain")
    def register_domain(
        self,
        context: RequestContext,
        name: DomainName,
        workflow_execution_retention_period_in_days: DurationInDays,
        description: Description = None,
        tags: ResourceTagList = None,
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
        description: Description = None,
        default_task_start_to_close_timeout: DurationInSecondsOptional = None,
        default_execution_start_to_close_timeout: DurationInSecondsOptional = None,
        default_task_list: TaskList = None,
        default_task_priority: TaskPriority = None,
        default_child_policy: ChildPolicy = None,
        default_lambda_role: Arn = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("RequestCancelWorkflowExecution")
    def request_cancel_workflow_execution(
        self,
        context: RequestContext,
        domain: DomainName,
        workflow_id: WorkflowId,
        run_id: WorkflowRunIdOptional = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("RespondActivityTaskCanceled")
    def respond_activity_task_canceled(
        self, context: RequestContext, task_token: TaskToken, details: Data = None, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("RespondActivityTaskCompleted")
    def respond_activity_task_completed(
        self, context: RequestContext, task_token: TaskToken, result: Data = None, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("RespondActivityTaskFailed")
    def respond_activity_task_failed(
        self,
        context: RequestContext,
        task_token: TaskToken,
        reason: FailureReason = None,
        details: Data = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("RespondDecisionTaskCompleted")
    def respond_decision_task_completed(
        self,
        context: RequestContext,
        task_token: TaskToken,
        decisions: DecisionList = None,
        execution_context: Data = None,
        task_list: TaskList = None,
        task_list_schedule_to_start_timeout: DurationInSecondsOptional = None,
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
        run_id: WorkflowRunIdOptional = None,
        input: Data = None,
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
        task_list: TaskList = None,
        task_priority: TaskPriority = None,
        input: Data = None,
        execution_start_to_close_timeout: DurationInSecondsOptional = None,
        tag_list: TagList = None,
        task_start_to_close_timeout: DurationInSecondsOptional = None,
        child_policy: ChildPolicy = None,
        lambda_role: Arn = None,
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
        run_id: WorkflowRunIdOptional = None,
        reason: TerminateReason = None,
        details: Data = None,
        child_policy: ChildPolicy = None,
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
