from localstack.aws.api import RequestContext, handler
from localstack.aws.api.logs import (
    CreateLogGroupRequest,
    CreateLogStreamRequest,
    DeleteLogGroupRequest,
    DeleteLogStreamRequest,
    DescribeLogGroupsRequest,
    DescribeLogGroupsResponse,
    DescribeLogStreamsRequest,
    DescribeLogStreamsResponse,
    FilteredLogEvent,
    FilterLogEventsRequest,
    FilterLogEventsResponse,
    GetLogEventsRequest,
    GetLogEventsResponse,
    InvalidParameterException,
    ListLogGroupsRequest,
    ListLogGroupsResponse,
    LogGroupClass,
    LogGroupSummary,
    LogsApi,
    OutputLogEvent,
    PutLogEventsRequest,
    PutLogEventsResponse,
    RejectedLogEventsInfo,
    ResourceAlreadyExistsException,
    ResourceNotFoundException, ValidationException,
)
from localstack.services.logs.db import db_helper
from localstack.services.logs.models import LogGroup, LogStream, logs_stores
from localstack.services.plugins import ServiceLifecycleHook
from localstack.utils.aws import arns
from localstack.utils.time import now_utc


class LogsProviderV2(ServiceLifecycleHook, LogsApi):
    """
    New provider for CloudWatch Logs.
    """

    @handler("CreateLogGroup", expand=False)
    def create_log_group(
        self,
        context: RequestContext,
        request: CreateLogGroupRequest,
    ) -> None:
        store = logs_stores[context.account_id][context.region]
        log_group_name = request["logGroupName"]

        if log_group_name in store.log_groups:
            raise ResourceAlreadyExistsException(f"Log group '{log_group_name}' already exists.")

        region = context.region
        account_id = context.account_id
        arn = arns.log_group_arn(log_group_name, account_id, region)
        store.log_groups[log_group_name] = LogGroup(
            logGroupName=log_group_name,
            creationTime=now_utc(),
            arn=f"{arn}:*",
            logGroupArn=arn,
            logGroupClass=request.get("logGroupClass", LogGroupClass.STANDARD),
            storedBytes=0,
            metricFilterCount=0
        )
        store.log_streams[log_group_name] = {}

    @handler("DescribeLogGroups", expand=False)
    def describe_log_groups(
        self,
        context: RequestContext,
        request: DescribeLogGroupsRequest,
    ) -> DescribeLogGroupsResponse:
        store = logs_stores[context.account_id][context.region]
        log_groups = list(store.log_groups.values())
        log_group_name_prefix = request.get("logGroupNamePrefix")
        log_group_name_pattern = request.get("logGroupNamePattern")

        if log_group_name_prefix and log_group_name_pattern:
            raise InvalidParameterException(
                "LogGroup name prefix and LogGroup name pattern are mutually exclusive parameters."
            )

        if log_group_name_prefix:
            log_groups = [
                lg for lg in log_groups if lg["logGroupName"].startswith(log_group_name_prefix)
            ]

        if log_group_name_pattern:
            log_groups = [
                lg for lg in log_groups if log_group_name_pattern in lg["logGroupName"]
            ]

        return DescribeLogGroupsResponse(logGroups=log_groups)

    @handler("ListLogGroups", expand=False)
    def list_log_groups(
        self, context: RequestContext, request: ListLogGroupsRequest
    ) -> ListLogGroupsResponse:
        store = logs_stores[context.account_id][context.region]
        log_groups = list(store.log_groups.values())
        log_group_name_pattern = request.get("logGroupNamePattern")

        if log_group_name_pattern:
            log_groups = [log_group for log_group in log_groups if log_group_name_pattern in log_group["logGroupName"]]

        groups = [
            LogGroupSummary(
                logGroupName=lg["logGroupName"],
                logGroupArn=lg["logGroupArn"],
                logGroupClass=LogGroupClass.STANDARD,
            )
            for lg in log_groups
        ]
        return ListLogGroupsResponse(logGroups=groups)

    @handler("DeleteLogGroup", expand=False)
    def delete_log_group(
        self,
        context: RequestContext,
        request: DeleteLogGroupRequest,
    ) -> None:
        store = logs_stores[context.account_id][context.region]
        log_group_name = request["logGroupName"]
        del store.log_groups[log_group_name]
        del store.log_streams[log_group_name]

    @handler("CreateLogStream", expand=False)
    def create_log_stream(
        self,
        context: RequestContext,
        request: CreateLogStreamRequest,
    ) -> None:
        store = logs_stores[context.account_id][context.region]
        log_group_name = request["logGroupName"]
        log_stream_name = request["logStreamName"]

        if log_group_name not in store.log_groups:
            raise ResourceNotFoundException("The specified log group does not exist.")
        if log_stream_name in store.log_streams.get(log_group_name, {}):
            raise ResourceAlreadyExistsException("The specified log stream does not exist.")

        region = context.region
        account_id = context.account_id
        arn = arns.log_stream_arn(log_group_name, log_stream_name, account_id, region)
        store.log_streams[log_group_name][log_stream_name] = LogStream(
            logStreamName=log_stream_name,
            creationTime=now_utc(),
            arn=arn,
            storedBytes=0,
        )

    @handler("DescribeLogStreams", expand=False)
    def describe_log_streams(
        self,
        context: RequestContext,
        request: DescribeLogStreamsRequest,
    ) -> DescribeLogStreamsResponse:
        store = logs_stores[context.account_id][context.region]
        log_group_name = request.get("logGroupName")
        log_group_identifier = request.get("logGroupIdentifier")
        log_stream_name_prefix = request.get("logStreamNamePrefix")

        if log_group_name and log_group_identifier:
            raise ValidationException(
                "LogGroup name and LogGroup ARN are mutually exclusive parameters."
            )

        if log_group_identifier:
            log_group_name = log_group_identifier.split(":")[-1]

        if log_group_name not in store.log_groups:
            raise ResourceNotFoundException("The specified log group does not exist.")

        log_streams = list(store.log_streams[log_group_name].values())

        if log_stream_name_prefix:
            log_streams = [
                ls for ls in log_streams if ls["logStreamName"].startswith(log_stream_name_prefix)
            ]
        elif log_group_name:
            log_streams = [
                ls for ls in log_streams if log_group_name in ls["arn"]
            ]

        return DescribeLogStreamsResponse(logStreams=log_streams)

    @handler("DeleteLogStream", expand=False)
    def delete_log_stream(
        self,
        context: RequestContext,
        request: DeleteLogStreamRequest,
    ) -> None:
        store = logs_stores[context.account_id][context.region]
        log_group_name = request["logGroupName"]
        log_stream_name = request["logStreamName"]

        if log_group_name not in store.log_groups:
            raise ResourceNotFoundException("The specified log group does not exist.")
        if log_stream_name not in store.log_streams.get(log_group_name, {}):
            raise ResourceNotFoundException("The specified log group does not exist.")

        del store.log_streams[log_group_name][log_stream_name]

    @handler("PutLogEvents", expand=False)
    def put_log_events(
        self,
        context: RequestContext,
        request: PutLogEventsRequest,
    ) -> PutLogEventsResponse:
        store = logs_stores[context.account_id][context.region]
        log_group_name = request["logGroupName"]
        log_stream_name = request["logStreamName"]
        log_events = request["logEvents"]

        if log_group_name not in store.log_groups:
            raise ResourceNotFoundException("The specified log group does not exist.")
        if log_stream_name not in store.log_streams.get(log_group_name, {}):
            raise ResourceNotFoundException("The specified log stream does not exist.")

        db_helper.put_log_events(
            log_group_name,
            log_stream_name,
            log_events,
            context.region,
            context.account_id,
        )
        return PutLogEventsResponse(rejectedLogEventsInfo=RejectedLogEventsInfo())

    @handler("GetLogEvents", expand=False)
    def get_log_events(
        self,
        context: RequestContext,
        request: GetLogEventsRequest,
    ) -> GetLogEventsResponse:
        region = context.region
        account_id = context.account_id

        store = logs_stores[context.account_id][context.region]
        log_group_name = request["logGroupName"]
        log_stream_name = request["logStreamName"]
        if log_group_name not in store.log_groups:
            raise ResourceNotFoundException("The specified log group does not exist.")
        if log_stream_name not in store.log_streams.get(log_group_name, {}):
            raise ResourceNotFoundException("The specified log stream does not exist.")
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
            events = [
                OutputLogEvent(timestamp=data["timestamp"], message=data["message"])
                for data in events_data
            ]
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
