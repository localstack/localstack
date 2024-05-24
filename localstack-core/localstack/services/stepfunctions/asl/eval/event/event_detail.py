from typing import Optional, TypedDict

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
    activityFailedEventDetails: Optional[ActivityFailedEventDetails]
    activityScheduleFailedEventDetails: Optional[ActivityScheduleFailedEventDetails]
    activityScheduledEventDetails: Optional[ActivityScheduledEventDetails]
    activityStartedEventDetails: Optional[ActivityStartedEventDetails]
    activitySucceededEventDetails: Optional[ActivitySucceededEventDetails]
    activityTimedOutEventDetails: Optional[ActivityTimedOutEventDetails]
    taskFailedEventDetails: Optional[TaskFailedEventDetails]
    taskScheduledEventDetails: Optional[TaskScheduledEventDetails]
    taskStartFailedEventDetails: Optional[TaskStartFailedEventDetails]
    taskStartedEventDetails: Optional[TaskStartedEventDetails]
    taskSubmitFailedEventDetails: Optional[TaskSubmitFailedEventDetails]
    taskSubmittedEventDetails: Optional[TaskSubmittedEventDetails]
    taskSucceededEventDetails: Optional[TaskSucceededEventDetails]
    taskTimedOutEventDetails: Optional[TaskTimedOutEventDetails]
    executionFailedEventDetails: Optional[ExecutionFailedEventDetails]
    executionStartedEventDetails: Optional[ExecutionStartedEventDetails]
    executionSucceededEventDetails: Optional[ExecutionSucceededEventDetails]
    executionAbortedEventDetails: Optional[ExecutionAbortedEventDetails]
    executionTimedOutEventDetails: Optional[ExecutionTimedOutEventDetails]
    mapStateStartedEventDetails: Optional[MapStateStartedEventDetails]
    mapIterationStartedEventDetails: Optional[MapIterationEventDetails]
    mapIterationSucceededEventDetails: Optional[MapIterationEventDetails]
    mapIterationFailedEventDetails: Optional[MapIterationEventDetails]
    mapIterationAbortedEventDetails: Optional[MapIterationEventDetails]
    lambdaFunctionFailedEventDetails: Optional[LambdaFunctionFailedEventDetails]
    lambdaFunctionScheduleFailedEventDetails: Optional[LambdaFunctionScheduleFailedEventDetails]
    lambdaFunctionScheduledEventDetails: Optional[LambdaFunctionScheduledEventDetails]
    lambdaFunctionStartFailedEventDetails: Optional[LambdaFunctionStartFailedEventDetails]
    lambdaFunctionSucceededEventDetails: Optional[LambdaFunctionSucceededEventDetails]
    lambdaFunctionTimedOutEventDetails: Optional[LambdaFunctionTimedOutEventDetails]
    stateEnteredEventDetails: Optional[StateEnteredEventDetails]
    stateExitedEventDetails: Optional[StateExitedEventDetails]
    mapRunStartedEventDetails: Optional[MapRunStartedEventDetails]
    mapRunFailedEventDetails: Optional[MapRunFailedEventDetails]
