
from typing import List, Optional, Dict, Any

from localstack.aws.api import RequestContext, handler
from localstack.aws.api.logs import (
    LogsApi,
    DescribeLogGroupsResponse,
    DescribeLogStreamsResponse,
    PutLogEventsResponse,
    RejectedLogEventsInfo,
    CreateLogGroupRequest,
    DescribeLogGroupsRequest,
    CreateLogStreamRequest,
    DescribeLogStreamsRequest,
    PutLogEventsRequest,
    DeleteLogGroupRequest,
    DeleteLogStreamRequest,
    GetLogEventsResponse,
    FilterLogEventsResponse,
    ResourceNotFoundException,
    ResourceAlreadyExistsException,
    InvalidParameterException,
    LogGroup,
    LogStream,
    OutputLogEvent,
    FilteredLogEvent, GetLogEventsRequest, FilterLogEventsRequest,
)
from localstack.services.logs.db import db_helper
from localstack.services.plugins import ServiceLifecycleHook


class LogsProviderV2(ServiceLifecycleHook, LogsApi):
    """
    New provider for CloudWatch Logs.
    """

    def _get_exception_for_value_error(self, e: ValueError, log_group_name: str, log_stream_name: Optional[str] = None):
        if str(e) == "ResourceAlreadyExistsException":
            if log_stream_name:
                return ResourceAlreadyExistsException(f"Log stream '{log_stream_name}' already exists in log group '{log_group_name}'.")
            return ResourceAlreadyExistsException(f"Log group '{log_group_name}' already exists.")
        if str(e) == "ResourceNotFoundException":
            if log_stream_name:
                return ResourceNotFoundException(f"Log stream '{log_stream_name}' not found in log group '{log_group_name}'.")
            return ResourceNotFoundException(f"Log group '{log_group_name}' not found.")
        return e


    @handler("CreateLogGroup", expand=False)
    def create_log_group(
        self,
        context: RequestContext,
        request: CreateLogGroupRequest,
    ) -> None:
        region = context.region
        account_id = context.account_id
        log_group_name = request["logGroupName"]
        arn = f"arn:aws:logs:{region}:{account_id}:log-group:{log_group_name}"
        try:
            db_helper.create_log_group(arn, log_group_name, region, account_id)
        except ValueError as e:
            raise self._get_exception_for_value_error(e, log_group_name)

    @handler("DescribeLogGroups", expand=False)
    def describe_log_groups(
        self,
        context: RequestContext,
        request: DescribeLogGroupsRequest,
    ) -> DescribeLogGroupsResponse:
        region = context.region
        account_id = context.account_id
        log_group_name_prefix = request.get("logGroupNamePrefix")
        log_group_name_pattern = request.get("logGroupNamePattern")
        log_group_name = request.get("logGroupName") # New parameter

        if log_group_name_prefix and log_group_name_pattern:
            raise InvalidParameterException(
                "LogGroup name prefix and LogGroup name pattern are mutually exclusive parameters."
            )
        if log_group_name and (log_group_name_prefix or log_group_name_pattern):
            raise InvalidParameterException(
                "LogGroup name cannot be used with LogGroup name prefix or LogGroup name pattern."
            )

        log_groups_data = db_helper.describe_log_groups(
            region, account_id, log_group_name, log_group_name_prefix, log_group_name_pattern
        )
        log_groups = [LogGroup(arn=data["arn"], logGroupName=data["logGroupName"]) for data in log_groups_data]
        return DescribeLogGroupsResponse(logGroups=log_groups)

    @handler("DeleteLogGroup", expand=False)
    def delete_log_group(
        self,
        context: RequestContext,
        request: DeleteLogGroupRequest,
    ) -> None:
        region = context.region
        account_id = context.account_id
        log_group_name = request["logGroupName"]
        try:
            db_helper.delete_log_group(log_group_name, region, account_id)
        except ValueError as e:
            raise self._get_exception_for_value_error(e, log_group_name)

    @handler("CreateLogStream", expand=False)
    def create_log_stream(
        self,
        context: RequestContext,
        request: CreateLogStreamRequest,
    ) -> None:
        region = context.region
        account_id = context.account_id
        log_group_name = request["logGroupName"]
        log_stream_name = request["logStreamName"]
        arn = f"arn:aws:logs:{region}:{account_id}:log-group:{log_group_name}:log-stream:{log_stream_name}"
        try:
            db_helper.create_log_stream(arn, log_stream_name, log_group_name, region, account_id)
        except ValueError as e:
            raise self._get_exception_for_value_error(e, log_group_name, log_stream_name)

    @handler("DescribeLogStreams", expand=False)
    def describe_log_streams(
        self,
        context: RequestContext,
        request: DescribeLogStreamsRequest,
    ) -> DescribeLogStreamsResponse:
        region = context.region
        account_id = context.account_id
        log_group_name = request["logGroupName"]
        try:
            log_streams_data = db_helper.describe_log_streams(log_group_name, region, account_id)
            log_streams = [LogStream(arn=data["arn"], logStreamName=data["logStreamName"]) for data in log_streams_data]
            return DescribeLogStreamsResponse(logStreams=log_streams)
        except ValueError as e:
            raise self._get_exception_for_value_error(e, log_group_name)

    @handler("DeleteLogStream", expand=False)
    def delete_log_stream(
        self,
        context: RequestContext,
        request: DeleteLogStreamRequest,
    ) -> None:
        region = context.region
        account_id = context.account_id
        log_group_name = request["logGroupName"]
        log_stream_name = request["logStreamName"]
        try:
            db_helper.delete_log_stream(log_group_name, log_stream_name, region, account_id)
        except ValueError as e:
            raise self._get_exception_for_value_error(e, log_group_name, log_stream_name)

    @handler("PutLogEvents", expand=False)
    def put_log_events(
        self,
        context: RequestContext,
        request: PutLogEventsRequest,
    ) -> PutLogEventsResponse:
        region = context.region
        account_id = context.account_id
        log_group_name = request["logGroupName"]
        log_stream_name = request["logStreamName"]
        log_events = [{"timestamp": e["timestamp"], "message": e["message"]} for e in request["logEvents"]] # Convert to dict
        try:
            db_helper.put_log_events(log_group_name, log_stream_name, log_events, region, account_id)
            return PutLogEventsResponse(rejectedLogEventsInfo=RejectedLogEventsInfo())
        except ValueError as e:
            raise self._get_exception_for_value_error(e, log_group_name, log_stream_name)

    @handler("GetLogEvents", expand=False)
    def get_log_events(
        self,
        context: RequestContext,
        request: GetLogEventsRequest,
    ) -> GetLogEventsResponse:
        region = context.region
        account_id = context.account_id
        log_group_name = request["logGroupName"]
        log_stream_name = request["logStreamName"]
        try:
            events_data = db_helper.get_log_events(
                log_group_name,
                log_stream_name,
                region,
                account_id,
                request.get("startTime"),
                request.get("endTime"),
                request.get("limit"),
                request.get("startFromHead"),
            )
            events = [OutputLogEvent(timestamp=data["timestamp"], message=data["message"]) for data in events_data]
            return GetLogEventsResponse(events=events)
        except ValueError as e:
            raise self._get_exception_for_value_error(e, log_group_name, log_stream_name)

    @handler("FilterLogEvents", expand=False)
    def filter_log_events(
        self,
        context: RequestContext,
        request: FilterLogEventsRequest,
    ) -> FilterLogEventsResponse:
        region = context.region
        account_id = context.account_id
        log_group_name = request["logGroupName"]
        try:
            events_data = db_helper.filter_log_events(
                log_group_name,
                region,
                account_id,
                request.get("logStreamNames"),
                request.get("startTime"),
                request.get("endTime"),
                request.get("filterPattern"),
                request.get("limit"),
            )
            events = [
                FilteredLogEvent(
                    logStreamName=data["logStreamName"],
                    timestamp=data["timestamp"],
                    message=data["message"],
                    eventId=data["eventId"],
                )
                for data in events_data
            ]
            return FilterLogEventsResponse(events=events)
        except ValueError as e:
            raise self._get_exception_for_value_error(e, log_group_name)
