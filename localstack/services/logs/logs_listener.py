import json
import logging
import re

from requests.models import Request

from localstack.constants import APPLICATION_AMZ_JSON_1_1, TEST_AWS_ACCOUNT_ID
from localstack.services.generic_proxy import ProxyListener
from localstack.utils.aws import aws_stack
from localstack.utils.common import is_number, to_str

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
    from moto.logs.models import (  # TODO: create separate RegionBackend class to store state
        logs_backends,
    )

    data = data if isinstance(data, dict) else json.loads(data)
    log_events = data.get("logEvents") or []
    logs_backend = logs_backends[aws_stack.get_region()]
    metric_filters = logs_backend.filters.metric_filters
    client = aws_stack.connect_to_service("cloudwatch")
    for metric_filter in metric_filters:
        pattern = metric_filter.get("filterPattern", "")
        if log_events_match_filter_pattern(pattern, log_events):
            for tf in metric_filter.get("metricTransformations", []):
                value = tf.get("metricValue") or "1"
                if "$size" in value:
                    LOG.info("Expression not yet supported for log filter metricValue: %s" % value)
                value = float(value) if is_number(value) else 1
                data = [{"MetricName": tf["metricName"], "Value": value}]
                try:
                    client.put_metric_data(Namespace=tf["metricNamespace"], MetricData=data)
                except Exception as e:
                    LOG.info("Unable to put metric data for matching CloudWatch log events: %s" % e)


def log_events_match_filter_pattern(filter_pattern, log_events):
    def matches(event):
        # TODO: implement full support for filter pattern expressions:
        # https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/FilterAndPatternSyntax.html
        return re.match(filter_pattern, event.get("message") or "")

    filter_pattern = (filter_pattern or "").strip() or "*"
    filter_pattern = filter_pattern.replace("*", ".*")
    log_events = log_events if isinstance(log_events, list) else [log_events]
    for event in log_events:
        if matches(event):
            return True


# instantiate listener
UPDATE_LOGS = ProxyListenerCloudWatchLogs()
