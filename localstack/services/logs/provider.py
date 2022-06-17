import base64
import io
import json
import logging
from gzip import GzipFile
from typing import Callable, Dict

from moto.core.utils import unix_time_millis
from moto.logs import models as logs_models
from moto.logs.exceptions import InvalidParameterException, ResourceNotFoundException
from moto.logs.models import LogGroup as MotoLogGroup
from moto.logs.models import LogsBackend
from moto.logs.models import LogStream as MotoLogStream
from moto.logs.models import logs_backends

from localstack.aws.accounts import get_aws_account_id
from localstack.aws.api import RequestContext
from localstack.aws.api.logs import (
    InputLogEvents,
    LogGroupName,
    LogsApi,
    LogStreamName,
    PutLogEventsResponse,
    SequenceToken,
)
from localstack.aws.proxy import AwsApiListener
from localstack.constants import APPLICATION_AMZ_JSON_1_1
from localstack.services.messages import Request, Response
from localstack.services.moto import MotoFallbackDispatcher, call_moto
from localstack.services.plugins import ServiceLifecycleHook
from localstack.utils.aws import aws_stack
from localstack.utils.common import is_number
from localstack.utils.patch import patch

LOG = logging.getLogger(__name__)


class LogsProvider(LogsApi, ServiceLifecycleHook):
    def __init__(self):
        super().__init__()
        self.cw_client = aws_stack.connect_to_service("cloudwatch")

    def put_log_events(
        self,
        context: RequestContext,
        log_group_name: LogGroupName,
        log_stream_name: LogStreamName,
        log_events: InputLogEvents,
        sequence_token: SequenceToken = None,
    ) -> PutLogEventsResponse:
        logs_backend = logs_backends[aws_stack.get_region()]
        metric_filters = logs_backend.filters.metric_filters
        for metric_filter in metric_filters:
            pattern = metric_filter.get("filterPattern", "")
            transformations = metric_filter.get("metricTransformations", [])
            matches = get_pattern_matcher(pattern)
            for log_event in log_events:
                if matches(pattern, log_event):
                    for tf in transformations:
                        value = tf.get("metricValue") or "1"
                        if "$size" in value:
                            LOG.info(
                                "Expression not yet supported for log filter metricValue", value
                            )
                        value = float(value) if is_number(value) else 1
                        data = [{"MetricName": tf["metricName"], "Value": value}]
                        try:
                            self.cw_client.put_metric_data(
                                Namespace=tf["metricNamespace"], MetricData=data
                            )
                        except Exception as e:
                            LOG.info(
                                "Unable to put metric data for matching CloudWatch log events", e
                            )
        return call_moto(context)


class LogsAwsApiListener(AwsApiListener):
    def __init__(self):
        self.provider = LogsProvider()
        super().__init__("logs", MotoFallbackDispatcher(self.provider))

    def request(self, request: Request) -> Response:
        response = super().request(request)
        # Fix Incorrect response content-type header from cloudwatch logs #1343.
        # True for all logs api responses.
        response.headers["content-type"] = APPLICATION_AMZ_JSON_1_1
        return response


def get_pattern_matcher(pattern: str) -> Callable[[str, Dict], bool]:
    """Returns a pattern matcher. Can be patched by plugins to return a more sophisticated pattern matcher."""
    return lambda _pattern, _log_event: True


@patch(LogsBackend.put_subscription_filter)
def moto_put_subscription_filter(fn, self, *args, **kwargs):
    log_group_name = args[0]
    filter_name = args[1]
    filter_pattern = args[2]
    destination_arn = args[3]
    role_arn = args[4]

    log_group = self.groups.get(log_group_name)

    if not log_group:
        raise ResourceNotFoundException("The specified log group does not exist.")

    if ":lambda:" in destination_arn:
        client = aws_stack.connect_to_service("lambda")
        lambda_name = aws_stack.lambda_function_name(destination_arn)
        try:
            client.get_function(FunctionName=lambda_name)
        except Exception:
            raise InvalidParameterException(
                "destinationArn for vendor lambda cannot be used with roleArn"
            )

    elif ":kinesis:" in destination_arn:
        client = aws_stack.connect_to_service("kinesis")
        stream_name = aws_stack.kinesis_stream_name(destination_arn)
        try:
            client.describe_stream(StreamName=stream_name)
        except Exception:
            raise InvalidParameterException(
                "Could not deliver test message to specified Kinesis stream. "
                "Check if the given kinesis stream is in ACTIVE state. "
            )

    elif ":firehose:" in destination_arn:
        client = aws_stack.connect_to_service("firehose")
        firehose_name = aws_stack.firehose_name(destination_arn)
        try:
            client.describe_delivery_stream(DeliveryStreamName=firehose_name)
        except Exception:
            raise InvalidParameterException(
                "Could not deliver test message to specified Firehose stream. "
                "Check if the given Firehose stream is in ACTIVE state."
            )

    else:
        service = aws_stack.extract_service_from_arn(destination_arn)
        raise InvalidParameterException(
            f"PutSubscriptionFilter operation cannot work with destinationArn for vendor {service}"
        )

    if filter_pattern:
        for stream in log_group.streams.values():
            stream.filter_pattern = filter_pattern

    log_group.put_subscription_filter(filter_name, filter_pattern, destination_arn, role_arn)


@patch(MotoLogStream.put_log_events, pass_target=False)
def moto_put_log_events(self, log_group_name, log_stream_name, log_events):
    # TODO: call/patch upstream method here, instead of duplicating the code!
    self.last_ingestion_time = int(unix_time_millis())
    self.stored_bytes += sum([len(log_event["message"]) for log_event in log_events])
    events = [logs_models.LogEvent(self.last_ingestion_time, log_event) for log_event in log_events]
    self.events += events
    self.upload_sequence_token += 1

    # apply filterpattern -> only forward what matches the pattern
    if self.filter_pattern:
        # TODO only patched in pro
        matches = get_pattern_matcher(self.filter_pattern)
        events = [
            logs_models.LogEvent(self.last_ingestion_time, event)
            for event in log_events
            if matches(self.filter_pattern, event)
        ]

    if events and self.destination_arn:
        log_events = [
            {
                "id": str(event.event_id),
                "timestamp": event.timestamp,
                "message": event.message,
            }
            for event in events
        ]

        data = {
            "messageType": "DATA_MESSAGE",
            "owner": get_aws_account_id(),
            "logGroup": log_group_name,
            "logStream": log_stream_name,
            "subscriptionFilters": [self.filter_name],
            "logEvents": log_events,
        }

        output = io.BytesIO()
        with GzipFile(fileobj=output, mode="w") as f:
            f.write(json.dumps(data, separators=(",", ":")).encode("utf-8"))
        payload_gz_encoded = output.getvalue()
        event = {"awslogs": {"data": base64.b64encode(output.getvalue()).decode("utf-8")}}

        if ":lambda:" in self.destination_arn:
            client = aws_stack.connect_to_service("lambda")
            lambda_name = aws_stack.lambda_function_name(self.destination_arn)
            client.invoke(FunctionName=lambda_name, Payload=json.dumps(event))
        if ":kinesis:" in self.destination_arn:
            client = aws_stack.connect_to_service("kinesis")
            stream_name = aws_stack.kinesis_stream_name(self.destination_arn)
            client.put_record(
                StreamName=stream_name,
                Data=payload_gz_encoded,
                PartitionKey=log_group_name,
            )
        if ":firehose:" in self.destination_arn:
            client = aws_stack.connect_to_service("firehose")
            firehose_name = aws_stack.firehose_name(self.destination_arn)
            client.put_record(
                DeliveryStreamName=firehose_name,
                Record={"Data": payload_gz_encoded},
            )
    return "{:056d}".format(self.upload_sequence_token)


@patch(MotoLogStream.filter_log_events)
def moto_filter_log_events(
    filter_log_events, self, start_time, end_time, filter_pattern, *args, **kwargs
):
    # moto currently raises an exception if filter_patterns is None, so we skip it
    events = filter_log_events(
        self, start_time=start_time, end_time=end_time, filter_pattern=None, *args, **kwargs
    )

    if not filter_pattern:
        return events

    matches = get_pattern_matcher(filter_pattern)
    return [event for event in events if matches(filter_pattern, event)]


@patch(MotoLogGroup.create_log_stream)
def moto_create_log_stream(target, self, log_stream_name):
    target(self, log_stream_name)
    stream = self.streams[log_stream_name]
    filters = self.describe_subscription_filters()
    stream.filter_pattern = filters[0]["filterPattern"] if filters else None
