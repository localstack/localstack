import sys
from typing import Dict, List, Optional

if sys.version_info >= (3, 8):
    from typing import TypedDict
else:
    from typing_extensions import TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

DescribeJobExecutionJobId = str
DetailsKey = str
DetailsValue = str
IncludeExecutionState = bool
IncludeJobDocument = bool
JobDocument = str
JobId = str
ThingName = str
errorMessage = str


class JobExecutionStatus(str):
    QUEUED = "QUEUED"
    IN_PROGRESS = "IN_PROGRESS"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    TIMED_OUT = "TIMED_OUT"
    REJECTED = "REJECTED"
    REMOVED = "REMOVED"
    CANCELED = "CANCELED"


class CertificateValidationException(ServiceException):
    message: Optional[errorMessage]


class InvalidRequestException(ServiceException):
    message: Optional[errorMessage]


class InvalidStateTransitionException(ServiceException):
    message: Optional[errorMessage]


class ResourceNotFoundException(ServiceException):
    message: Optional[errorMessage]


class ServiceUnavailableException(ServiceException):
    message: Optional[errorMessage]


class TerminalStateException(ServiceException):
    message: Optional[errorMessage]


BinaryBlob = bytes


class ThrottlingException(ServiceException):
    message: Optional[errorMessage]
    payload: Optional[BinaryBlob]


ApproximateSecondsBeforeTimedOut = int
ExecutionNumber = int


class DescribeJobExecutionRequest(ServiceRequest):
    jobId: DescribeJobExecutionJobId
    thingName: ThingName
    includeJobDocument: Optional[IncludeJobDocument]
    executionNumber: Optional[ExecutionNumber]


VersionNumber = int
LastUpdatedAt = int
StartedAt = int
QueuedAt = int
DetailsMap = Dict[DetailsKey, DetailsValue]


class JobExecution(TypedDict, total=False):
    jobId: Optional[JobId]
    thingName: Optional[ThingName]
    status: Optional[JobExecutionStatus]
    statusDetails: Optional[DetailsMap]
    queuedAt: Optional[QueuedAt]
    startedAt: Optional[StartedAt]
    lastUpdatedAt: Optional[LastUpdatedAt]
    approximateSecondsBeforeTimedOut: Optional[ApproximateSecondsBeforeTimedOut]
    versionNumber: Optional[VersionNumber]
    executionNumber: Optional[ExecutionNumber]
    jobDocument: Optional[JobDocument]


class DescribeJobExecutionResponse(TypedDict, total=False):
    execution: Optional[JobExecution]


ExpectedVersion = int


class GetPendingJobExecutionsRequest(ServiceRequest):
    thingName: ThingName


class JobExecutionSummary(TypedDict, total=False):
    jobId: Optional[JobId]
    queuedAt: Optional[QueuedAt]
    startedAt: Optional[StartedAt]
    lastUpdatedAt: Optional[LastUpdatedAt]
    versionNumber: Optional[VersionNumber]
    executionNumber: Optional[ExecutionNumber]


JobExecutionSummaryList = List[JobExecutionSummary]


class GetPendingJobExecutionsResponse(TypedDict, total=False):
    inProgressJobs: Optional[JobExecutionSummaryList]
    queuedJobs: Optional[JobExecutionSummaryList]


class JobExecutionState(TypedDict, total=False):
    status: Optional[JobExecutionStatus]
    statusDetails: Optional[DetailsMap]
    versionNumber: Optional[VersionNumber]


StepTimeoutInMinutes = int


class StartNextPendingJobExecutionRequest(ServiceRequest):
    thingName: ThingName
    statusDetails: Optional[DetailsMap]
    stepTimeoutInMinutes: Optional[StepTimeoutInMinutes]


class StartNextPendingJobExecutionResponse(TypedDict, total=False):
    execution: Optional[JobExecution]


class UpdateJobExecutionRequest(ServiceRequest):
    jobId: JobId
    thingName: ThingName
    status: JobExecutionStatus
    statusDetails: Optional[DetailsMap]
    stepTimeoutInMinutes: Optional[StepTimeoutInMinutes]
    expectedVersion: Optional[ExpectedVersion]
    includeJobExecutionState: Optional[IncludeExecutionState]
    includeJobDocument: Optional[IncludeJobDocument]
    executionNumber: Optional[ExecutionNumber]


class UpdateJobExecutionResponse(TypedDict, total=False):
    executionState: Optional[JobExecutionState]
    jobDocument: Optional[JobDocument]


class IotJobsDataApi:

    service = "iot-jobs-data"
    version = "2017-09-29"

    @handler("DescribeJobExecution")
    def describe_job_execution(
        self,
        context: RequestContext,
        job_id: DescribeJobExecutionJobId,
        thing_name: ThingName,
        include_job_document: IncludeJobDocument = None,
        execution_number: ExecutionNumber = None,
    ) -> DescribeJobExecutionResponse:
        raise NotImplementedError

    @handler("GetPendingJobExecutions")
    def get_pending_job_executions(
        self, context: RequestContext, thing_name: ThingName
    ) -> GetPendingJobExecutionsResponse:
        raise NotImplementedError

    @handler("StartNextPendingJobExecution")
    def start_next_pending_job_execution(
        self,
        context: RequestContext,
        thing_name: ThingName,
        status_details: DetailsMap = None,
        step_timeout_in_minutes: StepTimeoutInMinutes = None,
    ) -> StartNextPendingJobExecutionResponse:
        raise NotImplementedError

    @handler("UpdateJobExecution")
    def update_job_execution(
        self,
        context: RequestContext,
        job_id: JobId,
        thing_name: ThingName,
        status: JobExecutionStatus,
        status_details: DetailsMap = None,
        step_timeout_in_minutes: StepTimeoutInMinutes = None,
        expected_version: ExpectedVersion = None,
        include_job_execution_state: IncludeExecutionState = None,
        include_job_document: IncludeJobDocument = None,
        execution_number: ExecutionNumber = None,
    ) -> UpdateJobExecutionResponse:
        raise NotImplementedError
