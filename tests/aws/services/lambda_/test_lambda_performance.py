"""
Basic opt-in performance tests for Lambda. Usage:
1) Set TEST_PERFORMANCE=1
2) Set TEST_PERFORMANCE_RESULTS_DIR=$HOME/Downloads if you want to export performance results as CSV
3) Adjust repeat=100 to configure the number of repetitions
"""
import csv
import json
import logging
import os
import pathlib
import statistics
import threading
import time
import timeit
from datetime import datetime, timedelta

import pytest
from botocore.config import Config

from localstack import config
from localstack.aws.api.lambda_ import InvocationType, Runtime
from localstack.config import is_env_true
from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid, to_bytes
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
def test_lambda_event_invoke(create_lambda_function, s3_bucket, aws_client, aws_client_factory):
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

    lock = threading.Lock()
    request_ids = []
    error_counter = ThreadSafeCounter()
    num_invocations = 150
    invoke_barrier = threading.Barrier(num_invocations)

    def invoke(runner: int):
        nonlocal request_ids
        nonlocal error_counter
        nonlocal invoke_barrier
        try:
            payload = {"file_size_bytes": 1}
            invoke_barrier.wait()
            pool_config = Config(
                max_pool_connections=num_invocations,
            )
            lambda_client = aws_client_factory(config=pool_config).lambda_
            result = lambda_client.invoke(
                FunctionName=function_name,
                InvocationType=InvocationType.Event,
                Payload=to_bytes(json.dumps(payload)),
            )
            request_id = result["ResponseMetadata"]["RequestId"]
            with lock:
                request_ids.append(request_id)
        except Exception as e:
            print(f"runner-{runner} failed: {e}")
            error_counter.increment()

    start_time = datetime.utcnow()
    # Use threads to invoke Lambda function in parallel
    thread_list = []
    for i in range(1, num_invocations + 1):
        thread = threading.Thread(target=invoke, args=[i])
        thread.start()
        thread_list.append(thread)

    for thread in thread_list:
        thread.join()
    end_time = datetime.utcnow()
    diff = end_time - start_time
    print(f"N={num_invocations} took {diff.total_seconds()} seconds")
    assert error_counter.counter == 0

    sleep_seconds = 200
    print(f"Sleeping for {sleep_seconds} ...")
    time.sleep(sleep_seconds)

    # Validate CloudWatch invocation metric
    def assert_cloudwatch_metric():
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
        num_invocations_metric = 0
        for datapoint in response["Datapoints"]:
            num_invocations_metric += datapoint["Sum"]
        # assert num_invocations_metric == num_invocations
        return num_invocations_metric

    metric_count = assert_cloudwatch_metric()
    # retry(assert_cloudwatch_metric, retries=300, sleep=10)

    # Validate CloudWatch invocation logs
    def assert_log_events():
        # the default and maximum limit is 10k events
        response = aws_client.logs.filter_log_events(
            logGroupName=f"/aws/lambda/{function_name}",
        )
        assert "nextToken" not in response  # guard against pagination
        log_events = response["events"]
        invocation_count = len(
            [event["message"] for event in log_events if event["message"].startswith("REPORT")]
        )
        # assert invocation_count == num_invocations
        return invocation_count

    log_count = assert_log_events()
    # NOTE: slow against AWS (can take minutes and would likely require more retries)
    # retry(assert_log_events, retries=300, sleep=2)

    # Validate S3 object creation
    def assert_s3_objects():
        s3_keys_output = []
        paginator = aws_client.s3.get_paginator("list_objects_v2")
        page_iterator = paginator.paginate(Bucket=s3_bucket)
        for page in page_iterator:
            for obj in page.get("Contents", []):
                s3_keys_output.append(obj["Key"])
        # assert len(s3_keys_output) == num_invocations
        return len(s3_keys_output)

    s3_count = assert_s3_objects()

    assert [metric_count, log_count, s3_count] == [
        num_invocations,
        num_invocations,
        num_invocations,
    ]


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
