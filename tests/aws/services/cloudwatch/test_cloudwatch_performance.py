import logging
import threading
from datetime import datetime, timedelta
from typing import TYPE_CHECKING

import pytest
from botocore.config import Config

from localstack.config import is_env_true
from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid
from localstack.utils.sync import retry

if TYPE_CHECKING:
    from mypy_boto3_cloudwatch import CloudWatchClient

# reusing the same ENV as for test_lambda_performance
if not is_env_true("TEST_PERFORMANCE"):
    pytest.skip("Skip slow and resource-intensive tests", allow_module_level=True)


LOG = logging.getLogger(__name__)

CUSTOM_CLIENT_CONFIG_RETRY = Config(
    connect_timeout=60,
    read_timeout=60,
    retries={"max_attempts": 3},  # increase retries in case LS cannot accept connections anymore
    max_pool_connections=3000,
)

ACTION_LAMBDA = """
def handler(event, context):
    import json
    print(json.dumps(event))
    return {"success": True}
"""


def _delete_alarms(cloudwatch_client: "CloudWatchClient"):
    response = cloudwatch_client.describe_alarms()
    metric_alarms = [m["AlarmName"] for m in response["MetricAlarms"]]
    while next_token := response.get("NextToken"):
        response = cloudwatch_client.describe_alarms(NextToken=next_token)
        metric_alarms += [m["AlarmName"] for m in response["MetricAlarms"]]

    cloudwatch_client.delete_alarms(AlarmNames=metric_alarms)


class TestCloudWatchPerformance:
    @markers.aws.only_localstack
    def test_parallel_put_metric_data_list_metrics(self, aws_client, aws_client_factory):
        num_threads = 1200
        create_barrier = threading.Barrier(num_threads)
        error_counter = Counter()
        namespace = f"namespace-{short_uid()}"

        def _put_metric_list_metrics(runner: int):
            nonlocal error_counter
            nonlocal create_barrier
            nonlocal namespace
            create_barrier.wait()
            try:
                cw_client = aws_client_factory(config=CUSTOM_CLIENT_CONFIG_RETRY).cloudwatch
                if runner % 2:
                    cw_client.put_metric_data(
                        Namespace=namespace,
                        MetricData=[
                            {
                                "MetricName": f"metric-{runner}-1",
                                "Value": 25,
                                "Unit": "Seconds",
                            },
                            {
                                "MetricName": f"metric-{runner}-2",
                                "Value": runner + 1,
                                "Unit": "Seconds",
                            },
                        ],
                    )
                else:
                    cw_client.list_metrics()
            except Exception as e:
                LOG.exception(f"runner {runner} failed: {e}")
                error_counter.increment()

        start_time = datetime.utcnow()
        thread_list = []
        for i in range(1, num_threads + 1):
            thread = threading.Thread(target=_put_metric_list_metrics, args=[i])
            thread.start()
            thread_list.append(thread)

        for thread in thread_list:
            thread.join()

        end_time = datetime.utcnow()
        diff = end_time - start_time
        LOG.info(f"N={num_threads} took {diff.total_seconds()} seconds")

        assert error_counter.get_value() == 0
        metrics = []
        result = aws_client.cloudwatch.list_metrics(Namespace=namespace)
        metrics += result["Metrics"]

        while next_token := result.get("NextToken"):
            result = aws_client.cloudwatch.list_metrics(NextToken=next_token, Namespace=namespace)
            metrics += result["Metrics"]

        assert 1200 == len(metrics)  # every second thread inserted two metrics

    @markers.aws.only_localstack
    def test_run_100_alarms(
        self, aws_client, aws_client_factory, create_lambda_function, cleanups, account_id
    ):
        # create 100 alarms then add metrics
        # alarms should trigger
        fn_name = f"fn-cw-{short_uid()}"
        response = create_lambda_function(
            func_name=fn_name,
            handler_file=ACTION_LAMBDA,
            runtime="python3.11",
        )
        function_arn = response["CreateFunctionResponse"]["FunctionArn"]
        cleanups.append(lambda: _delete_alarms(aws_client.cloudwatch))
        random_id = short_uid()
        namespace = f"ns-{random_id}"
        for i in range(0, 100):
            # add 100 alarms (we can do this sequentially, they will start checking for matches in the background)
            alarm_name = f"alarm-{random_id}-{i}"
            aws_client.cloudwatch.put_metric_alarm(
                AlarmName=alarm_name,
                AlarmDescription="testing lambda alarm action",
                MetricName=f"metric-{i}",
                Namespace=namespace,
                Period=10,
                Threshold=2,
                Statistic="Average",
                OKActions=[],
                AlarmActions=[function_arn],
                EvaluationPeriods=1,
                ComparisonOperator="GreaterThanThreshold",
                TreatMissingData="ignore",
            )
            alarm_arn = aws_client.cloudwatch.describe_alarms(AlarmNames=[alarm_name])[
                "MetricAlarms"
            ][0]["AlarmArn"]

            # allow cloudwatch to trigger the lambda
            aws_client.lambda_.add_permission(
                FunctionName=fn_name,
                StatementId=f"AlarmAction-{i}",
                Action="lambda:InvokeFunction",
                Principal="lambda.alarms.cloudwatch.amazonaws.com",
                SourceAccount=account_id,
                SourceArn=alarm_arn,
            )
        # add metrics in parallel
        num_threads = 300
        create_barrier = threading.Barrier(num_threads)
        error_counter = Counter()

        def _put_metric_data(runner: int):
            nonlocal error_counter
            nonlocal create_barrier
            nonlocal namespace
            create_barrier.wait()
            try:
                metric_name = f"metric-{runner%100}"
                cw_client = aws_client_factory(config=CUSTOM_CLIENT_CONFIG_RETRY).cloudwatch
                cw_client.put_metric_data(
                    Namespace=namespace,
                    MetricData=[
                        {
                            "MetricName": metric_name,
                            "Value": 25,
                        },
                        {
                            "MetricName": metric_name,
                            "Value": 20 + runner,
                        },
                    ],
                )
            except Exception as e:
                LOG.exception(f"runner {runner} failed: {e}")
                error_counter.increment()

        start_time = datetime.utcnow()
        thread_list = []
        for i in range(0, num_threads):
            thread = threading.Thread(target=_put_metric_data, args=[i])
            thread.start()
            thread_list.append(thread)

        for thread in thread_list:
            thread.join()

        end_time = datetime.utcnow()
        diff = end_time - start_time
        LOG.info(f"N={num_threads} took {diff.total_seconds()} seconds")

        assert error_counter.get_value() == 0
        metrics = []
        result = aws_client.cloudwatch.list_metrics(Namespace=namespace)
        metrics += result["Metrics"]

        while next_token := result.get("NextToken"):
            result = aws_client.cloudwatch.list_metrics(NextToken=next_token, Namespace=namespace)
            metrics += result["Metrics"]

        assert 100 == len(metrics)

        def _assert_lambda_invocation():
            metric_query_params = {
                "Namespace": "AWS/Lambda",
                "MetricName": "Invocations",
                "Dimensions": [{"Name": "FunctionName", "Value": fn_name}],
                "StartTime": start_time,
                "EndTime": end_time + timedelta(minutes=20),
                "Period": 3600,  # in seconds
                "Statistics": ["Sum"],
            }
            response = aws_client.cloudwatch.get_metric_statistics(**metric_query_params)
            num_invocations_metric = 0
            for datapoint in response["Datapoints"]:
                num_invocations_metric += int(datapoint["Sum"])
            # assert num_invocations_metric == num_invocations
            assert num_invocations_metric == 100

        retry(
            lambda: _assert_lambda_invocation(),
            retries=200,
            sleep=5,
        )

    @markers.aws.only_localstack
    def test_sqs_queue_integration(self, aws_client, aws_client_factory):
        pass


class Counter:
    def __init__(self):
        self.value = 0
        self.lock = threading.Lock()

    def increment(self):
        with self.lock:
            self.value += 1

    def get_value(self):
        with self.lock:
            return self.value
