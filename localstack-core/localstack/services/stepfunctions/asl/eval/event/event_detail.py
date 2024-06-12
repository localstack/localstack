from typing import NotRequired, TypedDict

from localstack.aws.api.stepfunctions import (
    ActivityFailedEventDetails,
    ActivityScheduledEventDetails,
    ActivityScheduleFailedEventDetails,
    ActivityStartedEventDetails,
    ActivitySucceededEventDetails,
    ActivityTimedOutEventDetails,
    ExecutionAbortedEventDetails,
    ExecutionFailedEventDetails,
    ExecutionStartedEventDetails,
    ExecutionSucceededEventDetails,
    ExecutionTimedOutEventDetails,
    LambdaFunctionFailedEventDetails,
    LambdaFunctionScheduledEventDetails,
    LambdaFunctionScheduleFailedEventDetails,
    LambdaFunctionStartFailedEventDetails,
    LambdaFunctionSucceededEventDetails,
    LambdaFunctionTimedOutEventDetails,
    MapIterationEventDetails,
    MapRunFailedEventDetails,
    MapRunStartedEventDetails,
    MapStateStartedEventDetails,
    StateEnteredEventDetails,
    StateExitedEventDetails,
    TaskFailedEventDetails,
    TaskScheduledEventDetails,
    TaskStartedEventDetails,
    TaskStartFailedEventDetails,
    TaskSubmitFailedEventDetails,
    TaskSubmittedEventDetails,
    TaskSucceededEventDetails,
    TaskTimedOutEventDetails,
)


class EventDetails(TypedDict):
    activityFailedEventDetails: NotRequired[ActivityFailedEventDetails]
    activityScheduleFailedEventDetails: NotRequired[ActivityScheduleFailedEventDetails]
    activityScheduledEventDetails: NotRequired[ActivityScheduledEventDetails]
    activityStartedEventDetails: NotRequired[ActivityStartedEventDetails]
    activitySucceededEventDetails: NotRequired[ActivitySucceededEventDetails]
    activityTimedOutEventDetails: NotRequired[ActivityTimedOutEventDetails]
    taskFailedEventDetails: NotRequired[TaskFailedEventDetails]
    taskScheduledEventDetails: NotRequired[TaskScheduledEventDetails]
    taskStartFailedEventDetails: NotRequired[TaskStartFailedEventDetails]
    taskStartedEventDetails: NotRequired[TaskStartedEventDetails]
    taskSubmitFailedEventDetails: NotRequired[TaskSubmitFailedEventDetails]
    taskSubmittedEventDetails: NotRequired[TaskSubmittedEventDetails]
    taskSucceededEventDetails: NotRequired[TaskSucceededEventDetails]
    taskTimedOutEventDetails: NotRequired[TaskTimedOutEventDetails]
    executionFailedEventDetails: NotRequired[ExecutionFailedEventDetails]
    executionStartedEventDetails: NotRequired[ExecutionStartedEventDetails]
    executionSucceededEventDetails: NotRequired[ExecutionSucceededEventDetails]
    executionAbortedEventDetails: NotRequired[ExecutionAbortedEventDetails]
    executionTimedOutEventDetails: NotRequired[ExecutionTimedOutEventDetails]
    mapStateStartedEventDetails: NotRequired[MapStateStartedEventDetails]
    mapIterationStartedEventDetails: NotRequired[MapIterationEventDetails]
    mapIterationSucceededEventDetails: NotRequired[MapIterationEventDetails]
    mapIterationFailedEventDetails: NotRequired[MapIterationEventDetails]
    mapIterationAbortedEventDetails: NotRequired[MapIterationEventDetails]
    lambdaFunctionFailedEventDetails: NotRequired[LambdaFunctionFailedEventDetails]
    lambdaFunctionScheduleFailedEventDetails: NotRequired[LambdaFunctionScheduleFailedEventDetails]
    lambdaFunctionScheduledEventDetails: NotRequired[LambdaFunctionScheduledEventDetails]
    lambdaFunctionStartFailedEventDetails: NotRequired[LambdaFunctionStartFailedEventDetails]
    lambdaFunctionSucceededEventDetails: NotRequired[LambdaFunctionSucceededEventDetails]
    lambdaFunctionTimedOutEventDetails: NotRequired[LambdaFunctionTimedOutEventDetails]
    stateEnteredEventDetails: NotRequired[StateEnteredEventDetails]
    stateExitedEventDetails: NotRequired[StateExitedEventDetails]
    mapRunStartedEventDetails: NotRequired[MapRunStartedEventDetails]
    mapRunFailedEventDetails: NotRequired[MapRunFailedEventDetails]
