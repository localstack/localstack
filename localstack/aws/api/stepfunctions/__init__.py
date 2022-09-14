import sys
from datetime import datetime
from typing import List, Optional

if sys.version_info >= (3, 8):
    from typing import TypedDict
else:
    from typing_extensions import TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

Arn = str
ConnectorParameters = str
Definition = str
Enabled = bool
ErrorMessage = str
Identity = str
IncludeExecutionData = bool
IncludeExecutionDataGetExecutionHistory = bool
ListExecutionsPageToken = str
Name = str
PageSize = int
PageToken = str
ReverseOrder = bool
SensitiveCause = str
SensitiveData = str
SensitiveDataJobInput = str
SensitiveError = str
TagKey = str
TagValue = str
TaskToken = str
TraceHeader = str
UnsignedInteger = int
includedDetails = bool
truncated = bool


class ExecutionStatus(str):
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    TIMED_OUT = "TIMED_OUT"
    ABORTED = "ABORTED"


class HistoryEventType(str):
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


class LogLevel(str):
    ALL = "ALL"
    ERROR = "ERROR"
    FATAL = "FATAL"
    OFF = "OFF"


class StateMachineStatus(str):
    ACTIVE = "ACTIVE"
    DELETING = "DELETING"


class StateMachineType(str):
    STANDARD = "STANDARD"
    EXPRESS = "EXPRESS"


class SyncExecutionStatus(str):
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    TIMED_OUT = "TIMED_OUT"


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


class InvalidArn(ServiceException):
    code: str = "InvalidArn"
    sender_fault: bool = False
    status_code: int = 400


class InvalidDefinition(ServiceException):
    code: str = "InvalidDefinition"
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


class MissingRequiredParameter(ServiceException):
    code: str = "MissingRequiredParameter"
    sender_fault: bool = False
    status_code: int = 400


class ResourceNotFound(ServiceException):
    code: str = "ResourceNotFound"
    sender_fault: bool = False
    status_code: int = 400
    resourceName: Optional[Arn]


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


BilledDuration = int
BilledMemoryUsed = int


class BillingDetails(TypedDict, total=False):
    billedMemoryUsedInMB: Optional[BilledMemoryUsed]
    billedDurationInMilliseconds: Optional[BilledDuration]


class CloudWatchEventsExecutionDataDetails(TypedDict, total=False):
    included: Optional[includedDetails]


class CloudWatchLogsLogGroup(TypedDict, total=False):
    logGroupArn: Optional[Arn]


class Tag(TypedDict, total=False):
    key: Optional[TagKey]
    value: Optional[TagValue]


TagList = List[Tag]


class CreateActivityInput(ServiceRequest):
    name: Name
    tags: Optional[TagList]


class CreateActivityOutput(TypedDict, total=False):
    activityArn: Arn
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
    },
    total=False,
)


class CreateStateMachineOutput(TypedDict, total=False):
    stateMachineArn: Arn
    creationDate: Timestamp


class DeleteActivityInput(ServiceRequest):
    activityArn: Arn


class DeleteActivityOutput(TypedDict, total=False):
    pass


class DeleteStateMachineInput(ServiceRequest):
    stateMachineArn: Arn


class DeleteStateMachineOutput(TypedDict, total=False):
    pass


class DescribeActivityInput(ServiceRequest):
    activityArn: Arn


class DescribeActivityOutput(TypedDict, total=False):
    activityArn: Arn
    name: Name
    creationDate: Timestamp


class DescribeExecutionInput(ServiceRequest):
    executionArn: Arn


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


class DescribeStateMachineForExecutionInput(ServiceRequest):
    executionArn: Arn


class DescribeStateMachineForExecutionOutput(TypedDict, total=False):
    stateMachineArn: Arn
    name: Name
    definition: Definition
    roleArn: Arn
    updateDate: Timestamp
    loggingConfiguration: Optional[LoggingConfiguration]
    tracingConfiguration: Optional[TracingConfiguration]


class DescribeStateMachineInput(ServiceRequest):
    stateMachineArn: Arn


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
    },
    total=False,
)
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


ExecutionList = List[ExecutionListItem]


class ExecutionStartedEventDetails(TypedDict, total=False):
    input: Optional[SensitiveData]
    inputDetails: Optional[HistoryEventExecutionDataDetails]
    roleArn: Optional[Arn]


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


class StateExitedEventDetails(TypedDict, total=False):
    name: Name
    output: Optional[SensitiveData]
    outputDetails: Optional[HistoryEventExecutionDataDetails]


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


class LambdaFunctionScheduledEventDetails(TypedDict, total=False):
    resource: Arn
    input: Optional[SensitiveData]
    inputDetails: Optional[HistoryEventExecutionDataDetails]
    timeoutInSeconds: Optional[TimeoutInSeconds]


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
    },
    total=False,
)
HistoryEventList = List[HistoryEvent]


class GetExecutionHistoryOutput(TypedDict, total=False):
    events: HistoryEventList
    nextToken: Optional[PageToken]


class ListActivitiesInput(ServiceRequest):
    maxResults: Optional[PageSize]
    nextToken: Optional[PageToken]


class ListActivitiesOutput(TypedDict, total=False):
    activities: ActivityList
    nextToken: Optional[PageToken]


class ListExecutionsInput(ServiceRequest):
    stateMachineArn: Arn
    statusFilter: Optional[ExecutionStatus]
    maxResults: Optional[PageSize]
    nextToken: Optional[ListExecutionsPageToken]


class ListExecutionsOutput(TypedDict, total=False):
    executions: ExecutionList
    nextToken: Optional[ListExecutionsPageToken]


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


class UntagResourceInput(ServiceRequest):
    resourceArn: Arn
    tagKeys: TagKeyList


class UntagResourceOutput(TypedDict, total=False):
    pass


class UpdateStateMachineInput(ServiceRequest):
    stateMachineArn: Arn
    definition: Optional[Definition]
    roleArn: Optional[Arn]
    loggingConfiguration: Optional[LoggingConfiguration]
    tracingConfiguration: Optional[TracingConfiguration]


class UpdateStateMachineOutput(TypedDict, total=False):
    updateDate: Timestamp


class StepfunctionsApi:

    service = "stepfunctions"
    version = "2016-11-23"

    @handler("CreateActivity")
    def create_activity(
        self, context: RequestContext, name: Name, tags: TagList = None
    ) -> CreateActivityOutput:
        raise NotImplementedError

    @handler("CreateStateMachine", expand=False)
    def create_state_machine(
        self, context: RequestContext, request: CreateStateMachineInput
    ) -> CreateStateMachineOutput:
        raise NotImplementedError

    @handler("DeleteActivity")
    def delete_activity(self, context: RequestContext, activity_arn: Arn) -> DeleteActivityOutput:
        raise NotImplementedError

    @handler("DeleteStateMachine")
    def delete_state_machine(
        self, context: RequestContext, state_machine_arn: Arn
    ) -> DeleteStateMachineOutput:
        raise NotImplementedError

    @handler("DescribeActivity")
    def describe_activity(
        self, context: RequestContext, activity_arn: Arn
    ) -> DescribeActivityOutput:
        raise NotImplementedError

    @handler("DescribeExecution")
    def describe_execution(
        self, context: RequestContext, execution_arn: Arn
    ) -> DescribeExecutionOutput:
        raise NotImplementedError

    @handler("DescribeStateMachine")
    def describe_state_machine(
        self, context: RequestContext, state_machine_arn: Arn
    ) -> DescribeStateMachineOutput:
        raise NotImplementedError

    @handler("DescribeStateMachineForExecution")
    def describe_state_machine_for_execution(
        self, context: RequestContext, execution_arn: Arn
    ) -> DescribeStateMachineForExecutionOutput:
        raise NotImplementedError

    @handler("GetActivityTask")
    def get_activity_task(
        self, context: RequestContext, activity_arn: Arn, worker_name: Name = None
    ) -> GetActivityTaskOutput:
        raise NotImplementedError

    @handler("GetExecutionHistory")
    def get_execution_history(
        self,
        context: RequestContext,
        execution_arn: Arn,
        max_results: PageSize = None,
        reverse_order: ReverseOrder = None,
        next_token: PageToken = None,
        include_execution_data: IncludeExecutionDataGetExecutionHistory = None,
    ) -> GetExecutionHistoryOutput:
        raise NotImplementedError

    @handler("ListActivities")
    def list_activities(
        self, context: RequestContext, max_results: PageSize = None, next_token: PageToken = None
    ) -> ListActivitiesOutput:
        raise NotImplementedError

    @handler("ListExecutions")
    def list_executions(
        self,
        context: RequestContext,
        state_machine_arn: Arn,
        status_filter: ExecutionStatus = None,
        max_results: PageSize = None,
        next_token: ListExecutionsPageToken = None,
    ) -> ListExecutionsOutput:
        raise NotImplementedError

    @handler("ListStateMachines")
    def list_state_machines(
        self, context: RequestContext, max_results: PageSize = None, next_token: PageToken = None
    ) -> ListStateMachinesOutput:
        raise NotImplementedError

    @handler("ListTagsForResource")
    def list_tags_for_resource(
        self, context: RequestContext, resource_arn: Arn
    ) -> ListTagsForResourceOutput:
        raise NotImplementedError

    @handler("SendTaskFailure")
    def send_task_failure(
        self,
        context: RequestContext,
        task_token: TaskToken,
        error: SensitiveError = None,
        cause: SensitiveCause = None,
    ) -> SendTaskFailureOutput:
        raise NotImplementedError

    @handler("SendTaskHeartbeat")
    def send_task_heartbeat(
        self, context: RequestContext, task_token: TaskToken
    ) -> SendTaskHeartbeatOutput:
        raise NotImplementedError

    @handler("SendTaskSuccess")
    def send_task_success(
        self, context: RequestContext, task_token: TaskToken, output: SensitiveData
    ) -> SendTaskSuccessOutput:
        raise NotImplementedError

    @handler("StartExecution")
    def start_execution(
        self,
        context: RequestContext,
        state_machine_arn: Arn,
        name: Name = None,
        input: SensitiveData = None,
        trace_header: TraceHeader = None,
    ) -> StartExecutionOutput:
        raise NotImplementedError

    @handler("StartSyncExecution")
    def start_sync_execution(
        self,
        context: RequestContext,
        state_machine_arn: Arn,
        name: Name = None,
        input: SensitiveData = None,
        trace_header: TraceHeader = None,
    ) -> StartSyncExecutionOutput:
        raise NotImplementedError

    @handler("StopExecution")
    def stop_execution(
        self,
        context: RequestContext,
        execution_arn: Arn,
        error: SensitiveError = None,
        cause: SensitiveCause = None,
    ) -> StopExecutionOutput:
        raise NotImplementedError

    @handler("TagResource")
    def tag_resource(
        self, context: RequestContext, resource_arn: Arn, tags: TagList
    ) -> TagResourceOutput:
        raise NotImplementedError

    @handler("UntagResource")
    def untag_resource(
        self, context: RequestContext, resource_arn: Arn, tag_keys: TagKeyList
    ) -> UntagResourceOutput:
        raise NotImplementedError

    @handler("UpdateStateMachine")
    def update_state_machine(
        self,
        context: RequestContext,
        state_machine_arn: Arn,
        definition: Definition = None,
        role_arn: Arn = None,
        logging_configuration: LoggingConfiguration = None,
        tracing_configuration: TracingConfiguration = None,
    ) -> UpdateStateMachineOutput:
        raise NotImplementedError
