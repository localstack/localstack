"""
Basic opt-in performance tests for Lambda. Usage:
1) Set TEST_PERFORMANCE=1
2) Set TEST_PERFORMANCE_RESULTS_DIR=$HOME/Downloads if you want to export performance results as CSV
3) Adjust repeat=100 to configure the number of repetitions
"""
import csv
import json
import logging
import math
import os
import pathlib
import statistics
import threading
import time
import timeit
import uuid
from datetime import datetime, timedelta

import pytest
from botocore.config import Config

from localstack import config
from localstack.aws.api.lambda_ import InvocationType, Runtime
from localstack.config import is_env_true
from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid, to_bytes
from localstack.utils.sync import retry
from tests.aws.services.lambda_.test_lambda import (
    TEST_LAMBDA_PYTHON_ECHO,
    TEST_LAMBDA_PYTHON_S3_INTEGRATION,
)

# These performance tests are opt-in because we currently do not track performance systematically.
if not is_env_true("TEST_PERFORMANCE"):
    pytest.skip("Skip slow and resource-intensive tests", allow_module_level=True)


LOG = logging.getLogger(__name__)


# Custom botocore configuration suitable for performance testing.
# Using the aws_client_factory can
CLIENT_CONFIG = Config(
    # using shorter timeouts can help to detect issues earlier but longer timeouts give some room for high load
    connect_timeout=60,
    read_timeout=60,
    # retries might be necessary under high load, but could increase load through excessive retries
    retries={"max_attempts": 2},
    # 10 is the default but sometimes reducing it to 1 can help detecting issues. However, this should never be an issue
    # because it only relates to the number of cached connections.
    max_pool_connections=3000,
)


@markers.aws.validated
def test_invoke_warm_start(create_lambda_function, aws_client):
    function_name = f"test-lambda-perf-{short_uid()}"
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
    function_name = f"test-lambda-perf-{short_uid()}"
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
def test_number_of_function_versions(create_lambda_function, s3_bucket, aws_client):
    """Test how many function versions LocalStack can support.
    This test mainly idles and does one sync + async invoke as a sanity check."""
    # TODO: validate whether pollers for older function versions remain active because the verbose logs indicated that
    #   only two pollers were active despite many function versions. Try to async invoke an older function version.
    num_function_versions = 1000

    function_name = f"test-lambda-perf-{short_uid()}"
    create_lambda_function(
        handler_file=TEST_LAMBDA_PYTHON_S3_INTEGRATION,
        func_name=function_name,
        runtime=Runtime.python3_12,
        Environment={"Variables": {"S3_BUCKET_NAME": s3_bucket}},
    )

    for _ in range(num_function_versions):
        aws_client.lambda_.publish_version(FunctionName=function_name)

    # idle for a while to see if the pollers can manage the load and any errors occur
    time.sleep(90)

    result_1 = aws_client.lambda_.invoke(
        FunctionName=function_name,
        InvocationType=InvocationType.RequestResponse,
    )
    assert "FunctionError" not in result_1
    request_id_1 = result_1["ResponseMetadata"]["RequestId"]

    result_2 = aws_client.lambda_.invoke(
        FunctionName=function_name,
        InvocationType=InvocationType.Event,
    )
    assert "FunctionError" not in result_2
    request_id_2 = result_2["ResponseMetadata"]["RequestId"]

    # wait to complete the event invoke without causing extra load through polling
    LOG.info("Waiting for the event invoke to be processed ...")
    time.sleep(10)

    LOG.info("Validate invocations")
    s3_request_ids = get_s3_keys(aws_client, s3_bucket)
    assert set(s3_request_ids) == {request_id_1, request_id_2}


@markers.aws.unknown
def test_number_of_functions(create_lambda_function, s3_bucket, aws_client, aws_client_factory):
    """Test how many active functions LocalStack can support.
    This test invokes each function synchronously (all functions first) + asynchronously validates invokes using S3.
    """
    num_functions = 150
    uuid = short_uid()

    LOG.info("Create functions")
    for num in range(num_functions):
        function_name = f"test-lambda-perf-{uuid}-{num}"
        create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_S3_INTEGRATION,
            func_name=function_name,
            runtime=Runtime.python3_12,
            Environment={"Variables": {"S3_BUCKET_NAME": s3_bucket}},
        )

    # idle for a while to see if the pollers can manage the load and any errors occur
    LOG.info("Idle for steady state")
    time.sleep(30)

    LOG.info("Invoke each function once synchronously")
    request_ids = []
    lambda_client = aws_client_factory(config=CLIENT_CONFIG).lambda_
    for num in range(num_functions):
        function_name = f"test-lambda-perf-{uuid}-{num}"
        result_1 = lambda_client.invoke(
            FunctionName=function_name,
            InvocationType=InvocationType.RequestResponse,
        )
        assert "FunctionError" not in result_1
        request_id_1 = result_1["ResponseMetadata"]["RequestId"]
        request_ids.append(request_id_1)

    LOG.info("Invoke each function once asynchronously")
    for num in range(num_functions):
        function_name = f"test-lambda-perf-{uuid}-{num}"
        result_2 = lambda_client.invoke(
            FunctionName=function_name,
            InvocationType=InvocationType.Event,
        )
        assert "FunctionError" not in result_2
        request_id_2 = result_2["ResponseMetadata"]["RequestId"]
        request_ids.append(request_id_2)

    # wait to complete the event invoke without causing extra load through polling
    LOG.info("Waiting for event invokes to be processed ...")
    time.sleep(200)

    LOG.info("Validate invocations")
    s3_request_ids = get_s3_keys(aws_client, s3_bucket)
    assert set(s3_request_ids) == set(request_ids)


@markers.aws.validated
def test_lambda_event_invoke(create_lambda_function, s3_bucket, aws_client, aws_client_factory):
    """Test concurrent Lambda event invokes and validate the number of Lambda invocations using CloudWatch and S3."""
    num_invocations = 800

    function_name = f"test-lambda-perf-{short_uid()}"
    create_lambda_function(
        handler_file=TEST_LAMBDA_PYTHON_S3_INTEGRATION,
        func_name=function_name,
        runtime=Runtime.python3_12,
        Environment={"Variables": {"S3_BUCKET_NAME": s3_bucket}},
    )

    # Limit concurrency to avoid resource bottlenecks. This is typically not required because the ThreadPoolExecutor
    # in the pollers are limited to 32 threads. The actual concurrency depends on the number of available CPU cores.
    # aws_client.lambda_.put_function_concurrency(
    #     FunctionName=function_name, ReservedConcurrentExecutions=1
    # )

    lock = threading.Lock()
    request_ids = []
    error_counter = ThreadSafeCounter()
    invoke_barrier = threading.Barrier(num_invocations)

    def invoke(runner: int):
        nonlocal request_ids
        nonlocal error_counter
        nonlocal invoke_barrier
        try:
            payload = {"file_size_bytes": 1}
            lambda_client = aws_client_factory(config=CLIENT_CONFIG).lambda_
            # Wait until all threads are ready to invoke simultaneously
            invoke_barrier.wait()
            result = lambda_client.invoke(
                FunctionName=function_name,
                InvocationType=InvocationType.Event,
                Payload=to_bytes(json.dumps(payload)),
            )
            request_id = result["ResponseMetadata"]["RequestId"]
            with lock:
                request_ids.append(request_id)
        except Exception as e:
            LOG.error(f"runner-{runner} failed: {e}")
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
    LOG.info(f"N={num_invocations} took {diff.total_seconds()} seconds")
    assert error_counter.counter == 0

    # Sleeping here is a bit hacky, but we want to avoid polling for now because polling affects the results.
    sleep_seconds = 2000
    LOG.info(f"Sleeping for {sleep_seconds} ...")
    time.sleep(sleep_seconds)

    # Validate CloudWatch invocation metric
    def assert_cloudwatch_metric():
        metric_query_params = {
            "Namespace": "AWS/Lambda",
            "MetricName": "Invocations",
            "Dimensions": [{"Name": "FunctionName", "Value": function_name}],
            "StartTime": start_time,
            # CloudWatch Lambda metrics can be delayed is a known issue:
            # https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/Lambda-Insights-Troubleshooting.html
            "EndTime": end_time + timedelta(minutes=20),
            "Period": 3600,  # in seconds
            "Statistics": ["Sum"],
        }
        response = aws_client.cloudwatch.get_metric_statistics(**metric_query_params)
        num_invocations_metric = 0
        for datapoint in response["Datapoints"]:
            num_invocations_metric += int(datapoint["Sum"])
        # assert num_invocations_metric == num_invocations
        return num_invocations_metric

    metric_count = assert_cloudwatch_metric()
    # metric_count = retry(assert_cloudwatch_metric, retries=300, sleep=10)

    # Validate CloudWatch invocation logs
    def assert_log_events():
        # Using a paginator because the default and maximum limit is 10k events and
        # tests against AWS were missing invocations because they contained a `nextToken`
        paginator = aws_client.logs.get_paginator("filter_log_events")
        page_iterator = paginator.paginate(
            logGroupName=f"/aws/lambda/{function_name}",
        )
        invocation_count = 0
        for page in page_iterator:
            log_events = page["events"]
            invocation_count += len(
                [event["message"] for event in log_events if event["message"].startswith("REPORT")]
            )
        # assert invocation_count == num_invocations
        return invocation_count

    log_count = assert_log_events()
    # NOTE: slow against AWS (can take minutes and would likely require more retries)
    # log_count = retry(assert_log_events, retries=300, sleep=2)

    # Validate S3 object creation
    def assert_s3_objects():
        s3_keys_output = get_s3_keys(aws_client, s3_bucket)
        # assert len(s3_keys_output) == num_invocations
        return len(s3_keys_output)

    s3_count = assert_s3_objects()
    # s3_count = retry(assert_s3_objects, retries=300, sleep=2)

    # TODO: the CloudWatch metrics can be unreliable due to concurrency issues (new CW provider is WIP)
    # The s3_count does not consider re-tries, which have the same request_ids!
    assert [metric_count, log_count, s3_count] == [
        num_invocations,
        num_invocations,
        num_invocations,
    ]


@markers.aws.unknown
def test_lambda_event_source_mapping_sqs(
    create_lambda_function,
    s3_bucket,
    sqs_create_queue,
    sqs_get_queue_arn,
    aws_client,
    aws_client_factory,
):
    """Test SQS => Lambda event source mapping with concurrent event invokes and validate the number of invocations."""
    # TODO: define IAM permissions
    num_invocations = 2000
    batch_size = 1
    # This calculation might not be 100% accurate if the batch window is short, but it works for now
    target_invocations = math.ceil(num_invocations / batch_size)

    function_name = f"test-lambda-perf-{short_uid()}"
    create_lambda_function(
        handler_file=TEST_LAMBDA_PYTHON_S3_INTEGRATION,
        func_name=function_name,
        runtime=Runtime.python3_12,
        Environment={"Variables": {"S3_BUCKET_NAME": s3_bucket}},
    )

    queue_name = f"test-queue-{short_uid()}"
    queue_url = sqs_create_queue(QueueName=queue_name)
    queue_arn = sqs_get_queue_arn(queue_url)
    aws_client.lambda_.create_event_source_mapping(
        EventSourceArn=queue_arn,
        FunctionName=function_name,
        BatchSize=batch_size,
    )

    lock = threading.Lock()
    request_ids = []
    error_counter = ThreadSafeCounter()
    invoke_barrier = threading.Barrier(num_invocations)

    def invoke(runner: int):
        nonlocal request_ids
        nonlocal error_counter
        nonlocal invoke_barrier
        try:
            sqs_client = aws_client_factory(config=CLIENT_CONFIG).sqs
            invoke_barrier.wait()
            result = sqs_client.send_message(
                QueueUrl=queue_url, MessageBody=json.dumps({"message": str(uuid.uuid4())})
            )
            # SQS request_id does not match the Lambda request id because batching can apply
            request_id = result["ResponseMetadata"]["RequestId"]
            with lock:
                request_ids.append(request_id)
        except Exception as e:
            LOG.error(f"runner-{runner} failed: {e}")
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
    LOG.info(f"N={num_invocations} took {diff.total_seconds()} seconds")
    assert error_counter.counter == 0

    # Sleeping here is a bit hacky, but we want to avoid polling for now because polling affects the results.
    sleep_seconds = 400
    LOG.info(f"Sleeping for {sleep_seconds} ...")
    time.sleep(sleep_seconds)

    # Validate CloudWatch invocation metric
    def assert_cloudwatch_metric():
        metric_query_params = {
            "Namespace": "AWS/Lambda",
            "MetricName": "Invocations",
            "Dimensions": [{"Name": "FunctionName", "Value": function_name}],
            "StartTime": start_time,
            # CloudWatch Lambda metrics can be delayed is a known issue:
            # https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/Lambda-Insights-Troubleshooting.html
            "EndTime": end_time + timedelta(minutes=20),
            "Period": 3600,  # in seconds
            "Statistics": ["Sum"],
        }
        response = aws_client.cloudwatch.get_metric_statistics(**metric_query_params)
        num_invocations_metric = 0
        for datapoint in response["Datapoints"]:
            num_invocations_metric += int(datapoint["Sum"])
        # assert num_invocations_metric == num_invocations
        return num_invocations_metric

    metric_count = assert_cloudwatch_metric()
    # metric_count = retry(assert_cloudwatch_metric, retries=300, sleep=10)

    # Validate CloudWatch invocation logs
    def assert_log_events():
        # Using a paginator because the default and maximum limit is 10k events and
        # tests against AWS were missing invocations because they contained a `nextToken`
        paginator = aws_client.logs.get_paginator("filter_log_events")
        page_iterator = paginator.paginate(
            logGroupName=f"/aws/lambda/{function_name}",
        )
        invocation_count = 0
        for page in page_iterator:
            log_events = page["events"]
            invocation_count += len(
                [event["message"] for event in log_events if event["message"].startswith("REPORT")]
            )
        # assert invocation_count == num_invocations
        return invocation_count

    log_count = assert_log_events()
    # NOTE: slow against AWS (can take minutes and would likely require more retries)
    # log_count = retry(assert_log_events, retries=300, sleep=2)

    # Validate S3 object creation
    def assert_s3_objects():
        s3_keys_output = get_s3_keys(aws_client, s3_bucket)
        # assert len(s3_keys_output) == num_invocations
        return len(s3_keys_output)

    s3_count = assert_s3_objects()
    # s3_count = retry(assert_s3_objects, retries=300, sleep=2)

    # TODO: fix unreliable event source mapping (e.g., [168, 168, 169] with N=200)
    assert [metric_count, log_count, s3_count] == [
        target_invocations,
        target_invocations,
        target_invocations,
    ]


@markers.aws.unknown
def test_sns_subscription_lambda(
    create_lambda_function,
    s3_bucket,
    sns_create_topic,
    sns_subscription,
    aws_client,
    aws_client_factory,
):
    """Test SNS => Lambda subscription with concurrent event invokes and validate the number of invocations."""
    # TODO: define IAM permissions
    num_invocations = 800

    function_name = f"test-lambda-perf-{short_uid()}"
    lambda_creation_response = create_lambda_function(
        handler_file=TEST_LAMBDA_PYTHON_S3_INTEGRATION,
        func_name=function_name,
        runtime=Runtime.python3_12,
        Environment={"Variables": {"S3_BUCKET_NAME": s3_bucket}},
    )
    lambda_arn = lambda_creation_response["CreateFunctionResponse"]["FunctionArn"]

    topic_name = f"test-sns-{short_uid()}"
    topic_arn = sns_create_topic(Name=topic_name)["TopicArn"]
    aws_client.lambda_.add_permission(
        FunctionName=function_name,
        StatementId=f"test-statement-{short_uid()}",
        Action="lambda:InvokeFunction",
        Principal="sns.amazonaws.com",
        SourceArn=topic_arn,
    )

    subscription = sns_subscription(
        TopicArn=topic_arn,
        Protocol="lambda",
        Endpoint=lambda_arn,
    )

    def check_subscription():
        subscription_arn = subscription["SubscriptionArn"]
        subscription_attrs = aws_client.sns.get_subscription_attributes(
            SubscriptionArn=subscription_arn
        )
        assert subscription_attrs["Attributes"]["PendingConfirmation"] == "false"

    retry(check_subscription, retries=4, sleep=0.5)

    lock = threading.Lock()
    request_ids = []
    error_counter = ThreadSafeCounter()
    invoke_barrier = threading.Barrier(num_invocations)

    def invoke(runner: int):
        nonlocal request_ids
        nonlocal error_counter
        nonlocal invoke_barrier
        try:
            sns_client = aws_client_factory(config=CLIENT_CONFIG).sns
            invoke_barrier.wait()
            result = sns_client.publish(
                TopicArn=topic_arn, Subject="test-subject", Message=str(uuid.uuid4())
            )
            # TODO: validate against AWS whether the SNS request_id gets propagated into Lambda?!
            request_id = result["ResponseMetadata"]["RequestId"]
            with lock:
                request_ids.append(request_id)
        except Exception as e:
            LOG.error(f"runner-{runner} failed: {e}")
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
    LOG.info(f"N={num_invocations} took {diff.total_seconds()} seconds")
    assert error_counter.counter == 0

    sleep_seconds = 600
    LOG.info(f"Sleeping for {sleep_seconds} ...")
    time.sleep(sleep_seconds)

    # Validate CloudWatch invocation metric
    def assert_cloudwatch_metric():
        metric_query_params = {
            "Namespace": "AWS/Lambda",
            "MetricName": "Invocations",
            "Dimensions": [{"Name": "FunctionName", "Value": function_name}],
            "StartTime": start_time,
            # CloudWatch Lambda metrics can be delayed is a known issue:
            # https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/Lambda-Insights-Troubleshooting.html
            "EndTime": end_time + timedelta(minutes=20),
            "Period": 3600,  # in seconds
            "Statistics": ["Sum"],
        }
        response = aws_client.cloudwatch.get_metric_statistics(**metric_query_params)
        num_invocations_metric = 0
        for datapoint in response["Datapoints"]:
            num_invocations_metric += int(datapoint["Sum"])
        # assert num_invocations_metric == num_invocations
        return num_invocations_metric

    metric_count = assert_cloudwatch_metric()
    # metric_count = retry(assert_cloudwatch_metric, retries=300, sleep=10)

    # Validate CloudWatch invocation logs
    def assert_log_events():
        # Using a paginator because the default and maximum limit is 10k events and
        # tests against AWS were missing invocations because they contained a `nextToken`
        paginator = aws_client.logs.get_paginator("filter_log_events")
        page_iterator = paginator.paginate(
            logGroupName=f"/aws/lambda/{function_name}",
        )
        invocation_count = 0
        for page in page_iterator:
            log_events = page["events"]
            invocation_count += len(
                [event["message"] for event in log_events if event["message"].startswith("REPORT")]
            )
        # assert invocation_count == num_invocations
        return invocation_count

    log_count = assert_log_events()
    # NOTE: slow against AWS (can take minutes and would likely require more retries)
    # log_count = retry(assert_log_events, retries=300, sleep=2)

    # Validate S3 object creation first because it works synchronously and is most reliable
    def assert_s3_objects():
        s3_keys_output = get_s3_keys(aws_client, s3_bucket)
        # assert len(s3_keys_output) == num_invocations
        return len(s3_keys_output)

    s3_count = assert_s3_objects()
    # s3_count = retry(assert_s3_objects, retries=300, sleep=2)

    assert [metric_count, log_count, s3_count] == [
        num_invocations,
        num_invocations,
        num_invocations,
    ]


def get_s3_keys(aws_client, s3_bucket) -> [str]:
    s3_keys_output = []
    paginator = aws_client.s3.get_paginator("list_objects_v2")
    page_iterator = paginator.paginate(Bucket=s3_bucket)
    for page in page_iterator:
        for obj in page.get("Contents", []):
            s3_keys_output.append(obj["Key"])
    return s3_keys_output


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
