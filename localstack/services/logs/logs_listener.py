import base64
import io
import json
import logging
import re
from gzip import GzipFile
from typing import Callable, Dict

from moto.core.utils import unix_time_millis
from moto.logs import models as logs_models
from moto.logs.exceptions import InvalidParameterException, ResourceNotFoundException
from moto.logs.models import LogsBackend, LogStream
from requests.models import Request

from localstack.constants import APPLICATION_AMZ_JSON_1_1, TEST_AWS_ACCOUNT_ID
from localstack.services.generic_proxy import ProxyListener
from localstack.utils.aws import aws_stack
from localstack.utils.common import is_number, to_str
from localstack.utils.patch import Patches

LOG = logging.getLogger(__name__)


class ProxyListenerCloudWatchLogs(ProxyListener):
    def forward_request(self, method, path, data, headers):
        action = headers.get("X-Amz-Target") or ""
        action = action.split(".")[-1]

        if action == "PutLogEvents":
            publish_log_metrics_for_events(data)

        if method == "POST" and path == "/":
            if "nextToken" in to_str(data or ""):
                data = self._fix_next_token_request(data)
                headers["Content-Length"] = str(len(data))
                return Request(data=data, headers=headers, method=method)

        return True

    def return_response(self, method, path, data, headers, response):
        # Fix Incorrect response content-type header from cloudwatch logs #1343
        response.headers["content-type"] = APPLICATION_AMZ_JSON_1_1
        str_content = re.sub(
            r"arn:aws:logs:([^:]+):1:",
            r"arn:aws:logs:\1:%s:" % TEST_AWS_ACCOUNT_ID,
            to_str(response.content or ""),
        )
        response._content = str.encode(str_content)
        if "nextToken" in str_content:
            self._fix_next_token_response(response)
            response.headers["Content-Length"] = str(len(response._content))

    @staticmethod
    def _fix_next_token_request(data):
        # Fix for https://github.com/localstack/localstack/issues/1527
        pattern = r'"nextToken":\s*"([0-9]+)"'
        replacement = r'"nextToken": \1'
        return re.sub(pattern, replacement, to_str(data))

    @staticmethod
    def _fix_next_token_response(response):
        # Fix for https://github.com/localstack/localstack/issues/1527
        pattern = r'"nextToken":\s*([0-9]+)'
        replacement = r'"nextToken": "\1"'
        response._content = re.sub(pattern, replacement, to_str(response.content))


def publish_log_metrics_for_events(data):
    """Filter and publish log metrics for matching events"""
    from moto.logs.models import logs_backends

    data = data if isinstance(data, dict) else json.loads(data)
    log_events = data.get("logEvents") or []
    logs_backend = logs_backends[aws_stack.get_region()]
    metric_filters = logs_backend.filters.metric_filters
    client = aws_stack.connect_to_service("cloudwatch")
    for metric_filter in metric_filters:
        pattern = metric_filter.get("filterPattern", "")
        transformations = metric_filter.get("metricTransformations", [])
        matches = get_pattern_matcher(pattern)
        for log_event in log_events:
            if matches(pattern, log_event):
                for tf in transformations:
                    value = tf.get("metricValue") or "1"
                    if "$size" in value:
                        LOG.info("Expression not yet supported for log filter metricValue", value)
                    value = float(value) if is_number(value) else 1
                    data = [{"MetricName": tf["metricName"], "Value": value}]
                    try:
                        client.put_metric_data(Namespace=tf["metricNamespace"], MetricData=data)
                    except Exception as e:
                        LOG.info("Unable to put metric data for matching CloudWatch log events", e)


def get_pattern_matcher(pattern: str) -> Callable[[str, Dict], bool]:
    """Returns a pattern matcher. Can be patched by plugins to return a more sophisticated pattern matcher."""
    return lambda _pattern, _log_event: True


def moto_put_log_events(_, self, log_group_name, log_stream_name, log_events, sequence_token):
    # TODO: call/patch upstream method here, instead of duplicating the code!
    self.last_ingestion_time = int(unix_time_millis())
    self.stored_bytes += sum([len(log_event["message"]) for log_event in log_events])
    events = [logs_models.LogEvent(self.last_ingestion_time, log_event) for log_event in log_events]
    self.events += events
    self.upload_sequence_token += 1

    log_events = [
        {
            "id": event.event_id,
            "timestamp": event.timestamp,
            "message": event.message,
        }
        for event in events
    ]

    data = {
        "messageType": "DATA_MESSAGE",
        "owner": aws_stack.get_account_id(),
        "logGroup": log_group_name,
        "logStream": log_stream_name,
        "subscriptionFilters": [self.filter_name],
        "logEvents": log_events,
    }

    output = io.BytesIO()
    with GzipFile(fileobj=output, mode="w") as f:
        f.write(json.dumps(data, separators=(",", ":")).encode("utf-8"))
    payload_gz_encoded = base64.b64encode(output.getvalue()).decode("utf-8")
    event = {"awslogs": {"data": payload_gz_encoded}}

    if self.destination_arn:
        if ":lambda:" in self.destination_arn:
            client = aws_stack.connect_to_service("lambda")
            lambda_name = aws_stack.lambda_function_name(self.destination_arn)
            client.invoke(FunctionName=lambda_name, Payload=json.dumps(event))
        if ":kinesis:" in self.destination_arn:
            client = aws_stack.connect_to_service("kinesis")
            stream_name = aws_stack.kinesis_stream_name(self.destination_arn)
            client.put_record(
                StreamName=stream_name,
                Data=json.dumps(payload_gz_encoded),
                PartitionKey=log_group_name,
            )
        if ":firehose:" in self.destination_arn:
            client = aws_stack.connect_to_service("firehose")
            firehose_name = aws_stack.firehose_name(self.destination_arn)
            client.put_record(
                DeliveryStreamName=firehose_name,
                Record={"Data": json.dumps(payload_gz_encoded)},
            )


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
            "PutSubscriptionFilter operation cannot work with destinationArn for vendor %s"
            % service
        )

    log_group.put_subscription_filter(filter_name, filter_pattern, destination_arn, role_arn)


def moto_filter_log_events(
    filter_log_events,
    self,
    log_group_name,
    log_stream_names,
    start_time,
    end_time,
    limit,
    next_token,
    filter_pattern,
    interleaved,
):
    # moto currently raises an exception if filter_patterns is None, so we skip it
    events = filter_log_events(
        self,
        log_group_name,
        log_stream_names,
        start_time,
        end_time,
        limit,
        next_token,
        None,
        interleaved,
    )

    if not filter_pattern:
        return events

    matches = get_pattern_matcher(filter_pattern)
    return [event for event in events if matches(filter_pattern, event)]


def add_patches(patches: Patches):

    patches.function(LogsBackend.put_subscription_filter, moto_put_subscription_filter)
    patches.function(LogStream.put_log_events, moto_put_log_events)
    patches.function(LogStream.filter_log_events, moto_filter_log_events)


# instantiate listener
UPDATE_LOGS = ProxyListenerCloudWatchLogs()
