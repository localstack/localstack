import logging
import time
from datetime import datetime
from typing import Optional

from flask import Response

from localstack import config
from localstack.utils.analytics import event_publisher
from localstack.utils.aws import aws_stack
from localstack.utils.bootstrap import is_api_enabled
from localstack.utils.common import now_utc, to_str

LOG = logging.getLogger(__name__)


# ---------------
# Lambda metrics
# ---------------


def dimension_lambda(kwargs):
    func_name = _func_name(kwargs)
    return [{"Name": "FunctionName", "Value": func_name}]


def publish_lambda_metric(metric, value, kwargs):
    # publish metric only if CloudWatch service is available
    if not config.service_port("cloudwatch"):
        return
    cw_client = aws_stack.connect_to_service("cloudwatch")
    try:
        cw_client.put_metric_data(
            Namespace="AWS/Lambda",
            MetricData=[
                {
                    "MetricName": metric,
                    "Dimensions": dimension_lambda(kwargs),
                    "Timestamp": datetime.now(),
                    "Value": value,
                }
            ],
        )
    except Exception as e:
        LOG.info('Unable to put metric data for metric "%s" to CloudWatch: %s', metric, e)


def publish_lambda_duration(time_before, kwargs):
    time_after = now_utc()
    publish_lambda_metric("Duration", time_after - time_before, kwargs)


def publish_lambda_error(time_before, kwargs):
    publish_lambda_metric("Invocations", 1, kwargs)
    publish_lambda_metric("Errors", 1, kwargs)


def publish_lambda_result(time_before, result, kwargs):
    if isinstance(result, Response) and result.status_code >= 400:
        return publish_lambda_error(time_before, kwargs)
    publish_lambda_metric("Invocations", 1, kwargs)


def store_cloudwatch_logs(
    log_group_name,
    log_stream_name,
    log_output,
    start_time=None,
    auto_create_group: Optional[bool] = True,
):
    if not is_api_enabled("logs"):
        return
    start_time = start_time or int(time.time() * 1000)
    logs_client = aws_stack.connect_to_service("logs")
    log_output = to_str(log_output)

    if auto_create_group:
        # make sure that the log group exists, create it if not
        log_groups = logs_client.describe_log_groups()["logGroups"]
        log_groups = [lg["logGroupName"] for lg in log_groups]
        if log_group_name not in log_groups:
            try:
                logs_client.create_log_group(logGroupName=log_group_name)
            except Exception as e:
                if "ResourceAlreadyExistsException" in str(e):
                    # this can happen in certain cases, possibly due to a race condition
                    pass
                else:
                    raise e

    # create a new log stream for this lambda invocation
    try:
        logs_client.create_log_stream(logGroupName=log_group_name, logStreamName=log_stream_name)
    except Exception:  # TODO: narrow down
        pass

    # store new log events under the log stream
    finish_time = int(time.time() * 1000)
    # fix for log lines that were merged into a singe line, e.g., "log line 1 ... \x1b[32mEND RequestId ..."
    log_output = log_output.replace("\\x1b", "\n\\x1b")
    log_output = log_output.replace("\x1b", "\n\x1b")
    log_lines = log_output.split("\n")
    time_diff_per_line = float(finish_time - start_time) / float(len(log_lines))
    log_events = []
    for i, line in enumerate(log_lines):
        if not line:
            continue
        # simple heuristic: assume log lines were emitted in regular intervals
        log_time = start_time + float(i) * time_diff_per_line
        event = {"timestamp": int(log_time), "message": line}
        log_events.append(event)
    if not log_events:
        return
    logs_client.put_log_events(
        logGroupName=log_group_name, logStreamName=log_stream_name, logEvents=log_events
    )


# ---------------
# Helper methods
# ---------------


def _func_name(kwargs):
    func_name = kwargs.get("func_name")
    if not func_name:
        func_name = kwargs.get("func_arn").split(":function:")[1].split(":")[0]
    return func_name


def publish_event(time_before, result, kwargs):
    event_publisher.fire_event(
        event_publisher.EVENT_LAMBDA_INVOKE_FUNC,
        payload={
            "f": event_publisher.get_hash(_func_name(kwargs)),
            "d": now_utc() - time_before,
            "r": result[0],
        },
    )


def publish_result(ns, time_before, result, kwargs):
    if ns == "lambda":
        publish_lambda_result(time_before, result, kwargs)
        publish_event(time_before, "success", kwargs)
    else:
        LOG.info("Unexpected CloudWatch namespace: %s", ns)


def publish_error(ns, time_before, e, kwargs):
    if ns == "lambda":
        publish_lambda_error(time_before, kwargs)
        publish_event(time_before, "error", kwargs)
    else:
        LOG.info("Unexpected CloudWatch namespace: %s", ns)


def cloudwatched(ns):
    """@cloudwatched(...) decorator for annotating methods to be monitored via CloudWatch"""

    def wrapping(func):
        def wrapped(*args, **kwargs):
            time_before = now_utc()
            try:
                result = func(*args, **kwargs)
                publish_result(ns, time_before, result, kwargs)
            except Exception as e:
                publish_error(ns, time_before, e, kwargs)
                raise e
            finally:
                # TODO
                # time_after = now_utc()
                pass
            return result

        return wrapped

    return wrapping
