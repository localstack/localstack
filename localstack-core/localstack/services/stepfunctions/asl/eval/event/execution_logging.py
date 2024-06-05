from __future__ import annotations

import logging
from datetime import datetime
from typing import Final, NotRequired, Optional, TypedDict

from botocore.exceptions import ClientError
from mypy_boto3_logs.client import CloudWatchLogsClient
from mypy_boto3_logs.type_defs import InputLogEventTypeDef

from localstack.aws.api.stepfunctions import (
    HistoryEventType,
    InvalidLoggingConfiguration,
    LoggingConfiguration,
    LogLevel,
    LongArn,
)
from localstack.aws.connect import connect_to
from localstack.services.stepfunctions.asl.utils.encoding import to_json_str

LOG = logging.getLogger(__name__)

ExecutionEventLogDetails = dict

# The following event type sets are compiled according to AWS's
# log level definitions: https://docs.aws.amazon.com/step-functions/latest/dg/cloudwatch-log-level.html
_ERROR_LOG_EVENT_TYPES: Final[set[HistoryEventType]] = {
    HistoryEventType.ExecutionAborted,
    HistoryEventType.ExecutionFailed,
    HistoryEventType.ExecutionTimedOut,
    HistoryEventType.FailStateEntered,
    HistoryEventType.LambdaFunctionFailed,
    HistoryEventType.LambdaFunctionScheduleFailed,
    HistoryEventType.LambdaFunctionStartFailed,
    HistoryEventType.LambdaFunctionTimedOut,
    HistoryEventType.MapStateAborted,
    HistoryEventType.MapStateFailed,
    HistoryEventType.MapIterationAborted,
    HistoryEventType.MapIterationFailed,
    HistoryEventType.MapRunAborted,
    HistoryEventType.MapRunFailed,
    HistoryEventType.ParallelStateAborted,
    HistoryEventType.ParallelStateFailed,
    HistoryEventType.TaskFailed,
    HistoryEventType.TaskStartFailed,
    HistoryEventType.TaskStateAborted,
    HistoryEventType.TaskSubmitFailed,
    HistoryEventType.TaskTimedOut,
    HistoryEventType.WaitStateAborted,
}
_FATAL_LOG_EVENT_TYPES: Final[set[HistoryEventType]] = {
    HistoryEventType.ExecutionAborted,
    HistoryEventType.ExecutionFailed,
    HistoryEventType.ExecutionTimedOut,
}


# The LogStreamName used when creating the empty Log Stream when validating the logging configuration.
VALIDATION_LOG_STREAM_NAME: Final[str] = (
    "log_stream_created_by_aws_to_validate_log_delivery_subscriptions"
)


class CloudWatchLoggingConfiguration:
    state_machine_arn: Final[LongArn]
    log_level: Final[LogLevel]
    log_group_name: Final[str]
    log_stream_name: Final[str]
    include_execution_data: Final[bool]

    def __init__(
        self,
        state_machine_arn: LongArn,
        log_level: LogLevel,
        log_group_name: str,
        include_execution_data: bool,
    ):
        self.state_machine_arn = state_machine_arn
        self.log_level = log_level
        self.log_group_name = log_group_name
        # TODO: AWS appears to append a date and a serial number to the log
        #  stream name: more investigations are needed in this area.
        self.log_stream_name = f"states/{state_machine_arn}"
        self.include_execution_data = include_execution_data

    @staticmethod
    def extract_log_group_name_from(logging_configuration: LoggingConfiguration) -> Optional[str]:
        # Returns the log group name if the logging configuration specifies one, none otherwise.

        destinations = logging_configuration.get("destinations")
        if not destinations or len(destinations) > 1:  # Only one destination can be defined.
            return None

        log_group = destinations[0].get("cloudWatchLogsLogGroup")
        if not log_group:
            return None

        log_group_arn = log_group.get("logGroupArn")
        if not log_group_arn:
            return None

        log_group_arn_parts = log_group_arn.split(":log-group:")
        if not log_group_arn_parts:
            return None

        log_group_name = log_group_arn_parts[-1].split(":")[0]
        return log_group_name

    @staticmethod
    def from_logging_configuration(
        state_machine_arn: LongArn,
        logging_configuration: LoggingConfiguration,
    ) -> Optional[CloudWatchLoggingConfiguration]:
        log_level = logging_configuration.get("level", LogLevel.OFF)
        if log_level == LogLevel.OFF:
            return None

        log_group_name = CloudWatchLoggingConfiguration.extract_log_group_name_from(
            logging_configuration=logging_configuration
        )
        if not log_group_name:
            return None

        include_execution_data = logging_configuration["includeExecutionData"]

        return CloudWatchLoggingConfiguration(
            state_machine_arn=state_machine_arn,
            log_level=log_level,
            log_group_name=log_group_name,
            include_execution_data=include_execution_data,
        )

    def validate(self) -> None:
        # Asserts that the logging configuration can be used for logging.
        logs_client = connect_to().logs
        try:
            logs_client.create_log_stream(
                logGroupName=self.log_group_name, logStreamName=VALIDATION_LOG_STREAM_NAME
            )
        except ClientError as error:
            error_code = error.response["Error"]["Code"]
            if error_code != "ResourceAlreadyExistsException":
                raise InvalidLoggingConfiguration(
                    "Invalid Logging Configuration: Log Destination not found."
                )


class HistoryLog(TypedDict):
    id: str
    previous_event_id: str
    event_timestamp: datetime
    type: HistoryEventType
    execution_arn: LongArn
    details: NotRequired[ExecutionEventLogDetails]


class CloudWatchLoggingSession:
    execution_arn: Final[LongArn]
    configuration: Final[CloudWatchLoggingConfiguration]
    _logs_client: Final[CloudWatchLogsClient]
    _setup_failed: bool

    def __init__(self, execution_arn: LongArn, configuration: CloudWatchLoggingConfiguration):
        self.execution_arn = execution_arn
        self.configuration = configuration
        self._logs_client = connect_to().logs
        self._setup_failed = True

    def log_level_filter(self, history_event_type: HistoryEventType) -> bool:
        # Checks whether the history event type should be logged in this session.
        match self.configuration.log_level:
            case LogLevel.ALL:
                return True
            case LogLevel.OFF:
                return False
            case LogLevel.ERROR:
                return history_event_type in _ERROR_LOG_EVENT_TYPES
            case LogLevel.FATAL:
                return history_event_type in _FATAL_LOG_EVENT_TYPES

    def publish_history_log(self, history_log: HistoryLog) -> None:
        if self._setup_failed:
            return

        try:
            timestamp_value = int(history_log["event_timestamp"].timestamp()) * 1000
            message = to_json_str(history_log)
            self._logs_client.put_log_events(
                logGroupName=self.configuration.log_group_name,
                logStreamName=self.configuration.log_stream_name,
                logEvents=[
                    InputLogEventTypeDef(
                        timestamp=timestamp_value,
                        message=message,
                    )
                ],
            )
        except Exception as ignored:
            LOG.warning(
                f"State Machine execution log event could not be published due to an error: '{ignored}'"
            )

    def setup(self):
        # Create the log stream if one does not exist already.
        try:
            self._logs_client.create_log_stream(
                logGroupName=self.configuration.log_group_name,
                logStreamName=self.configuration.log_stream_name,
            )
            self._setup_failed = False
        except ClientError as error:
            LOG.error(
                f"Could not create execution log stream for execution '{self.execution_arn}' due to {error}"
            )
