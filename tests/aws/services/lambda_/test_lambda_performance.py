"""
Basic opt-in performance tests for Lambda. Usage:
1) Set TEST_PERFORMANCE=1
2) Set TEST_PERFORMANCE_RESULTS_DIR=$HOME/Downloads if you want to export performance results as CSV
3) Adjust repeat=100 to configure the number of repetitions
"""
import concurrent
import csv
import json
import logging
import os
import pathlib
import statistics
import threading
import timeit
from datetime import datetime, timedelta

import pytest

from localstack import config
from localstack.aws.api.lambda_ import InvocationType, Runtime
from localstack.config import is_env_true
from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid, to_bytes, to_str
from localstack.utils.sync import retry
from tests.aws.services.lambda_.test_lambda import (
    TEST_LAMBDA_PYTHON_ECHO,
    TEST_LAMBDA_PYTHON_S3_INTEGRATION,
)

# These performance tests are opt-in because we currently do not track performance systematically.
if not is_env_true("TEST_PERFORMANCE"):
    pytest.skip("Skip slow and resource-intensive tests", allow_module_level=True)


LOG = logging.getLogger(__name__)


@markers.aws.validated
def test_invoke_warm_start(create_lambda_function, aws_client):
    function_name = f"echo-func-{short_uid()}"
    create_lambda_function(
        handler_file=TEST_LAMBDA_PYTHON_ECHO,
        func_name=function_name,
        runtime=Runtime.python3_9,
    )

    def invoke():
        aws_client.lambda_.invoke(FunctionName=function_name)

    # Ignore initial cold start
    invoke()

    # Test warm starts
    repeat = 100
    timings = timeit.repeat(invoke, number=1, repeat=repeat)
    LOG.info(f" EXECUTION TIME (s) for {repeat} repetitions ".center(80, "="))
    LOG.info(format_summary(timings))
    export_csv(timings, "test_invoke_warm_start")


@markers.aws.only_localstack
def test_invoke_cold_start(create_lambda_function, aws_client, monkeypatch):
    monkeypatch.setattr(config, "LAMBDA_KEEPALIVE_MS", 0)
    function_name = f"echo-func-{short_uid()}"
    create_lambda_function(
        handler_file=TEST_LAMBDA_PYTHON_ECHO,
        func_name=function_name,
        runtime=Runtime.python3_9,
    )

    def invoke():
        aws_client.lambda_.invoke(FunctionName=function_name)

    # Ignore the initial cold start, which could be even slower due to init downloading
    invoke()

    # Test cold starts caused by the option LAMBDA_KEEPALIVE_MS=0
    repeat = 100
    # Optionally sleep in between repetitions to avoid delays caused by the previous container shutting down
    sleep_s = 4
    timings = timeit.repeat(
        invoke, number=1, repeat=repeat, setup=f"import time; time.sleep({sleep_s})"
    )
    LOG.info(f" EXECUTION TIME (s) for {repeat} repetitions ".center(80, "="))
    LOG.info(format_summary(timings))
    export_csv(timings, "test_invoke_cold_start")


class ThreadSafeCounter:
    def __init__(self):
        self.lock = threading.Lock()
        self.counter = 0

    def increment(self):
        with self.lock:
            self.counter += 1


@markers.aws.unknown
def test_lambda_event_invoke(create_lambda_function, s3_bucket, aws_client):
    function_name = f"echo-func-{short_uid()}"
    create_lambda_function(
        handler_file=TEST_LAMBDA_PYTHON_S3_INTEGRATION,
        func_name=function_name,
        runtime=Runtime.python3_12,
        Environment={"Variables": {"S3_BUCKET_NAME": s3_bucket}},
    )

    # Limit concurrency to avoid resource bottlenecks
    # aws_client.lambda_.put_function_concurrency(
    #     FunctionName=function_name, ReservedConcurrentExecutions=1
    # )

    s3_keys = []
    error_counter = ThreadSafeCounter()

    def invoke():
        nonlocal error_counter
        try:
            payload = {"file_size_bytes": 1024 * 1024}
            # TODO: switch to event after successful request response trial
            result = aws_client.lambda_.invoke(
                FunctionName=function_name,
                InvocationType=InvocationType.RequestResponse,
                Payload=to_bytes(json.dumps(payload)),
            )
        except Exception:
            error_counter.increment()
        # TODO: adjust for event invoke
        assert "FunctionError" not in result
        response_payload = json.loads(to_str(result["Payload"].read()))
        s3_keys.append(response_payload["s3_key"])

    start_time = datetime.utcnow()
    # Use ThreadPoolExecutor to invoke Lambda function in parallel
    num_invocations = 100
    with concurrent.futures.ThreadPoolExecutor(max_workers=num_invocations) as executor:
        # Use list comprehension to submit multiple tasks
        futures = [executor.submit(invoke) for _ in range(num_invocations)]

        # Wait for all tasks to complete
        concurrent.futures.wait(futures)
    end_time = datetime.utcnow()
    diff = end_time - start_time
    print(f"N={num_invocations} took {diff.total_seconds()} seconds")
    assert error_counter.counter == 0

    # Validate S3 object creation
    s3_keys_output = []
    paginator = aws_client.s3.get_paginator("list_objects_v2")
    page_iterator = paginator.paginate(Bucket=s3_bucket)
    for page in page_iterator:
        for obj in page.get("Contents", []):
            s3_keys_output.append(obj["Key"])
    assert len(s3_keys_output) == num_invocations

    # Validate CloudWatch invocation metric
    metric_query_params = {
        "Namespace": "AWS/Lambda",
        "MetricName": "Invocations",
        "Dimensions": [{"Name": "FunctionName", "Value": function_name}],
        "StartTime": start_time,
        "EndTime": end_time + timedelta(seconds=10),
        "Period": 3600,  # in seconds
        "Statistics": ["Sum"],
    }
    response = aws_client.cloudwatch.get_metric_statistics(**metric_query_params)
    num_invocations_metric = response["Datapoints"][0]["Sum"]
    assert num_invocations_metric == num_invocations

    # Validate CloudWatch invocation logs
    def assert_events():
        log_events = aws_client.logs.filter_log_events(
            logGroupName=f"/aws/lambda/{function_name}",
        )["events"]
        invocation_count = len(
            [event["message"] for event in log_events if event["message"].startswith("REPORT")]
        )
        assert invocation_count == num_invocations

    # NOTE: slow against AWS (can take minutes and would likely require more retries)
    retry(assert_events, retries=30, sleep=2)


def format_summary(timings: [float]) -> str:
    """Format summary statistics in seconds."""
    p99 = (
        statistics.quantiles(timings, n=100, method="inclusive")[98] if len(timings) > 1 else "N/A"
    )
    stats = [
        f"{min(timings)} (min)",
        f"{statistics.median(timings)} (median)",
        f"""{p99} (p99)""",
        f"{max(timings)} (max)",
    ]
    return ", ".join(stats)


def export_csv(timings: [float], label: str = "") -> None:
    """Export the given timings into a csv file if the environment variable TEST_PERFORMANCE_RESULTS_DIR is set."""
    if results_dir := os.environ.get("TEST_PERFORMANCE_RESULTS_DIR"):
        timestamp = datetime.now().strftime("%Y-%m-%dT%H-%M-%S")
        file_name = f"{timestamp}_{label}.csv"
        file_path = pathlib.Path(results_dir) / file_name
        file = open(file_path, "w")
        data = [[value] for value in timings]
        with file:
            write = csv.writer(file)
            write.writerows(data)
