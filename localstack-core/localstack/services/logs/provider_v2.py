import base64
import datetime
import io
import json
from collections.abc import Callable
from gzip import GzipFile

from moto.core.utils import unix_time_millis

from localstack.aws.api import RequestContext, handler
from localstack.aws.api.logs import (
    AmazonResourceName,
    ApplyOnTransformedLogs,
    CreateLogGroupRequest,
    CreateLogStreamRequest,
    DeleteLogGroupRequest,
    DeleteLogStreamRequest,
    DescribeLimit,
    DescribeLogGroupsRequest,
    DescribeLogGroupsResponse,
    DescribeLogStreamsRequest,
    DescribeLogStreamsResponse,
    DescribeSubscriptionFiltersResponse,
    DestinationArn,
    Distribution,
    EmitSystemFields,
    FieldSelectionCriteria,
    FilteredLogEvent,
    FilterLogEventsRequest,
    FilterLogEventsResponse,
    FilterName,
    FilterPattern,
    GetLogEventsRequest,
    GetLogEventsResponse,
    InvalidParameterException,
    ListLogGroupsRequest,
    ListLogGroupsResponse,
    ListTagsForResourceResponse,
    ListTagsLogGroupResponse,
    LogEvent,
    LogGroupClass,
    LogGroupName,
    LogGroupSummary,
    LogsApi,
    NextToken,
    OutputLogEvent,
    PutLogEventsRequest,
    PutLogEventsResponse,
    RejectedLogEventsInfo,
    ResourceAlreadyExistsException,
    ResourceNotFoundException,
    RoleArn,
    TagKeyList,
    TagList,
    Tags,
    ValidationException,
)
from localstack.aws.connect import connect_to
from localstack.services.logs.db import LogsDatabaseHelper
from localstack.services.logs.models import LogGroup, LogStream, SubscriptionFilter, logs_stores
from localstack.services.plugins import ServiceLifecycleHook
from localstack.utils.aws import arns
from localstack.utils.aws.client_types import ServicePrincipal
from localstack.utils.threads import start_worker_thread
from localstack.utils.time import now_utc


def get_pattern_matcher(pattern: str) -> Callable[[str, dict], bool]:
    """Returns a pattern matcher. Can be patched by plugins to return a more sophisticated pattern matcher."""
    return lambda _pattern, _log_event: True


class LogsProviderV2(ServiceLifecycleHook, LogsApi):
    def __init__(self):
        self.db_helper = LogsDatabaseHelper()

    def on_before_state_reset(self):
        self.db_helper.clear_tables()

    def on_after_state_reset(self):
        self.db_helper = LogsDatabaseHelper()

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
            metricFilterCount=0,
        )
        store.log_streams[log_group_name] = {}

        if tags := request.get("tags"):
            resource_arn = arns.log_group_arn(
                group_name=log_group_name, account_id=context.account_id, region_name=context.region
            )
            store = logs_stores[context.account_id][context.region]
            store.TAGS.setdefault(resource_arn, {}).update(tags)

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
            log_groups = [lg for lg in log_groups if log_group_name_pattern in lg["logGroupName"]]

        return DescribeLogGroupsResponse(logGroups=log_groups)

    @handler("ListLogGroups", expand=False)
    def list_log_groups(
        self, context: RequestContext, request: ListLogGroupsRequest
    ) -> ListLogGroupsResponse:
        store = logs_stores[context.account_id][context.region]
        log_groups = list(store.log_groups.values())
        log_group_name_pattern = request.get("logGroupNamePattern")

        if log_group_name_pattern:
            log_groups = [
                log_group
                for log_group in log_groups
                if log_group_name_pattern in log_group["logGroupName"]
            ]

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
            log_streams = [ls for ls in log_streams if log_group_name in ls["arn"]]

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
        log_group_name = request["logGroupName"]
        log_stream_name = request["logStreamName"]
        log_events = request["logEvents"]
        store = logs_stores[context.account_id][context.region]

        if log_group_name not in store.log_groups:
            raise ResourceNotFoundException("The specified log group does not exist.")
        if log_stream_name not in store.log_streams.get(log_group_name, {}):
            raise ResourceNotFoundException("The specified log stream does not exist.")

        self.db_helper.put_log_events(
            log_group_name,
            log_stream_name,
            log_events,
            context.region,
            context.account_id,
        )

        def _send_events_to_subscriptions(*_):
            self._send_events_to_subscription(
                log_group_name,
                log_stream_name,
                log_events,
                account_id=context.account_id,
                region=context.region,
            )

        def _send_events_to_metrics(*_):
            pass

        start_worker_thread(_send_events_to_subscriptions)

        return PutLogEventsResponse(rejectedLogEventsInfo=RejectedLogEventsInfo())

    def _send_events_to_subscription(
        self, log_group_name, log_stream_name, events, account_id, region
    ):
        store = logs_stores[account_id][region]
        subscription_filters = store.subscription_filters.get(log_group_name, [])
        for subscription_filter in subscription_filters:
            if subscription_filter.get("filterPattern"):
                matches = get_pattern_matcher(subscription_filter.filter_pattern)
                events = [
                    LogEvent(datetime.datetime.now(), event)
                    for event in events
                    if matches(subscription_filter.get("filterPattern"), event)
                ]

            if events and subscription_filter.get("destinationArn"):
                destination_arn = subscription_filter.get("destinationArn")
                log_events = [
                    {
                        "id": event.get("event_id", "0"),
                        "timestamp": event.get("timestamp"),
                        "message": event.get("message"),
                    }
                    for event in events
                ]

                data = {
                    "messageType": "DATA_MESSAGE",
                    "owner": account_id,  # AWS Account ID of the originating log data
                    "logGroup": log_group_name,
                    "logStream": log_stream_name,
                    "subscriptionFilters": [subscription_filter.get("filterName")],
                    "logEvents": log_events,
                }

                output = io.BytesIO()
                with GzipFile(fileobj=output, mode="w") as f:
                    f.write(json.dumps(data, separators=(",", ":")).encode("utf-8"))
                payload_gz_encoded = output.getvalue()
                event = {"awslogs": {"data": base64.b64encode(output.getvalue()).decode("utf-8")}}

                log_group_arn = arns.log_group_arn(log_group_name, account_id, region)
                arn_data = arns.parse_arn(destination_arn)

                if role_arn := subscription_filter.get("roleArn"):
                    factory = connect_to.with_assumed_role(
                        role_arn=role_arn,
                        service_principal=ServicePrincipal.logs,
                        region_name=arn_data["region"],
                    )
                else:
                    factory = connect_to(
                        aws_access_key_id=arn_data["account"], region_name=arn_data["region"]
                    )

                if ":lambda:" in destination_arn:
                    client = factory.lambda_.request_metadata(
                        source_arn=log_group_arn, service_principal=ServicePrincipal.logs
                    )
                    client.invoke(FunctionName=destination_arn, Payload=json.dumps(event))

                if ":kinesis:" in destination_arn:
                    client = factory.kinesis.request_metadata(
                        source_arn=log_group_arn, service_principal=ServicePrincipal.logs
                    )
                    stream_name = arns.kinesis_stream_name(destination_arn)
                    client.put_record(
                        StreamName=stream_name,
                        Data=payload_gz_encoded,
                        PartitionKey=log_group_name,
                    )

                if ":firehose:" in destination_arn:
                    client = factory.firehose.request_metadata(
                        source_arn=log_group_arn, service_principal=ServicePrincipal.logs
                    )
                    firehose_name = arns.firehose_name(destination_arn)
                    client.put_record(
                        DeliveryStreamName=firehose_name,
                        Record={"Data": payload_gz_encoded},
                    )

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
            events_data = self.db_helper.get_log_events(
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
            events_data = self.db_helper.filter_log_events(
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

    def list_tags_for_resource(
        self, context: RequestContext, resource_arn: AmazonResourceName, **kwargs
    ) -> ListTagsForResourceResponse:
        self._check_resource_arn_tagging(resource_arn)
        store = logs_stores[context.account_id][context.region]
        tags = store.TAGS.get(resource_arn, {})
        return ListTagsForResourceResponse(tags=tags)

    def untag_resource(
        self,
        context: RequestContext,
        resource_arn: AmazonResourceName,
        tag_keys: TagKeyList,
        **kwargs,
    ) -> None:
        self._check_resource_arn_tagging(resource_arn)
        store = logs_stores[context.account_id][context.region]
        tags_stored = store.TAGS.get(resource_arn, {})
        for tag in tag_keys:
            tags_stored.pop(tag, None)

    def untag_log_group(
        self, context: RequestContext, log_group_name: LogGroupName, tags: TagList, **kwargs
    ) -> None:
        # deprecated implementation -> new one: untag_resource
        self._verify_log_group_exists(
            group_name=log_group_name, account_id=context.account_id, region_name=context.region
        )
        resource_arn = arns.log_group_arn(
            group_name=log_group_name, account_id=context.account_id, region_name=context.region
        )
        store = logs_stores[context.account_id][context.region]
        tags_stored = store.TAGS.get(resource_arn, {})
        for tag in tags:
            tags_stored.pop(tag, None)

    def tag_resource(
        self, context: RequestContext, resource_arn: AmazonResourceName, tags: Tags, **kwargs
    ) -> None:
        self._check_resource_arn_tagging(resource_arn)
        store = logs_stores[context.account_id][context.region]
        store.TAGS.get(resource_arn, {}).update(tags or {})

    def tag_log_group(
        self, context: RequestContext, log_group_name: LogGroupName, tags: Tags, **kwargs
    ) -> None:
        # deprecated implementation -> new one: tag_resource
        self._verify_log_group_exists(
            group_name=log_group_name, account_id=context.account_id, region_name=context.region
        )
        resource_arn = arns.log_group_arn(
            group_name=log_group_name, account_id=context.account_id, region_name=context.region
        )
        store = logs_stores[context.account_id][context.region]
        store.TAGS.get(resource_arn, {}).update(tags or {})

    def list_tags_log_group(
        self, context: RequestContext, log_group_name: LogGroupName, **kwargs
    ) -> ListTagsLogGroupResponse:
        store = logs_stores[context.account_id][context.region]

        if log_group_name not in store.log_groups:
            raise ResourceNotFoundException("The specified log group does not exist.")

        resource_arn = arns.log_group_arn(
            group_name=log_group_name, account_id=context.account_id, region_name=context.region
        )
        tags = store.TAGS.get(resource_arn, {})
        return ListTagsLogGroupResponse(tags=tags)

    def _check_resource_arn_tagging(self, resource_arn):
        service = arns.extract_service_from_arn(resource_arn)
        region = arns.extract_region_from_arn(resource_arn)
        account = arns.extract_account_id_from_arn(resource_arn)

        # AWS currently only supports tagging for Log Group and Destinations
        # LS: we only verify if log group exists, and create tags for other resources
        if service.lower().startswith("log-group:"):
            self._verify_log_group_exists(
                service.split(":")[-1], account_id=account, region_name=region
            )

    def _verify_log_group_exists(self, group_name: LogGroupName, account_id: str, region_name: str):
        store = logs_stores[account_id][region_name]

        if group_name not in store.log_groups:
            raise ResourceNotFoundException("The specified log group does not exist.")

    def put_subscription_filter(
        self,
        context: RequestContext,
        log_group_name: LogGroupName,
        filter_name: FilterName,
        filter_pattern: FilterPattern,
        destination_arn: DestinationArn,
        role_arn: RoleArn | None = None,
        distribution: Distribution | None = None,
        apply_on_transformed_logs: ApplyOnTransformedLogs | None = None,
        field_selection_criteria: FieldSelectionCriteria | None = None,
        emit_system_fields: EmitSystemFields | None = None,
        **kwargs,
    ) -> None:
        self._verify_log_group_exists(log_group_name, context.account_id, context.region)

        store = logs_stores[context.account_id][context.region]
        log_group = store.log_groups.get(log_group_name)
        log_group_arn = log_group["logGroupArn"]

        if not log_group:
            raise ResourceNotFoundException("The specified log group does not exist.")

        arn_data = arns.parse_arn(destination_arn)

        if role_arn:
            factory = connect_to.with_assumed_role(
                role_arn=role_arn,
                service_principal=ServicePrincipal.logs,
                region_name=arn_data["region"],
            )
        else:
            factory = connect_to(
                aws_access_key_id=arn_data["account"], region_name=arn_data["region"]
            )

        if ":lambda:" in destination_arn:
            client = factory.lambda_.request_metadata(
                source_arn=log_group_arn, service_principal=ServicePrincipal.logs
            )
            try:
                client.get_function(FunctionName=destination_arn)
            except Exception:
                raise InvalidParameterException(
                    "destinationArn for vendor lambda cannot be used with roleArn"
                )

        elif ":kinesis:" in destination_arn:
            client = factory.kinesis.request_metadata(
                source_arn=log_group_arn, service_principal=ServicePrincipal.logs
            )
            stream_name = arns.kinesis_stream_name(destination_arn)
            try:
                # Kinesis-Local DescribeStream does not support StreamArn param, so use StreamName instead
                client.describe_stream(StreamName=stream_name)
            except Exception:
                raise InvalidParameterException(
                    "Could not deliver message to specified Kinesis stream. "
                    "Ensure that the Kinesis stream exists and is ACTIVE."
                )

        elif ":firehose:" in destination_arn:
            client = factory.firehose.request_metadata(
                source_arn=log_group_arn, service_principal=ServicePrincipal.logs
            )
            firehose_name = arns.firehose_name(destination_arn)
            try:
                client.describe_delivery_stream(DeliveryStreamName=firehose_name)
            except Exception:
                raise InvalidParameterException(
                    "Could not deliver message to specified Firehose stream. "
                    "Ensure that the Firehose stream exists and is ACTIVE."
                )

        else:
            raise InvalidParameterException(
                f"PutSubscriptionFilter operation cannot work with destinationArn for vendor {arn_data['service']}"
            )

        previous_filters = store.subscription_filters.get(log_group_name, [])
        previous_filters.append(
            SubscriptionFilter(
                filterName=filter_name,
                filterPattern=filter_pattern,
                destinationArn=destination_arn,
                roleArn=role_arn,
                logGroupName=log_group_name,
                distribution=distribution or Distribution.ByLogStream,
                creationTime=int(unix_time_millis()),
            )
        )

        store.subscription_filters.update({log_group_name: previous_filters})

    def describe_subscription_filters(
        self,
        context: RequestContext,
        log_group_name: LogGroupName,
        filter_name_prefix: FilterName | None = None,
        next_token: NextToken | None = None,
        limit: DescribeLimit | None = None,
        **kwargs,
    ) -> DescribeSubscriptionFiltersResponse:
        filter_name_prefix = filter_name_prefix or ""
        store = logs_stores[context.account_id][context.region]
        filters = store.subscription_filters.get(log_group_name, [])
        filters = [
            _filter for _filter in filters if _filter["filterName"].startswith(filter_name_prefix)
        ]
        return DescribeSubscriptionFiltersResponse(subscriptionFilters=filters)

    def delete_subscription_filter(
        self,
        context: RequestContext,
        log_group_name: LogGroupName,
        filter_name: FilterName,
        **kwargs,
    ) -> None:
        store = logs_stores[context.account_id][context.region]
        filters = store.subscription_filters.get(log_group_name, [])
        filters = [_filter for _filter in filters if _filter["filterName"] != filter_name]

        store.subscription_filters.update({log_group_name: filters})
