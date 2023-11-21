from datetime import datetime, timedelta
from typing import TYPE_CHECKING

import pytest

from localstack.testing.pytest import markers
from localstack.testing.pytest.snapshot import is_aws
from localstack.utils.strings import short_uid

if TYPE_CHECKING:
    from mypy_boto3_cloudwatch import CloudWatchClient
from localstack.utils.sync import retry

TEST_SUCCESSFUL_LAMBDA = """
def handler(event, context):
    return {"success": "ok"}
"""

TEST_FAILING_LAMBDA = """
def handler(event, context):
    raise Exception('fail on purpose')
"""


class TestCloudWatchLambdaMetrics:
    """
    Tests for metrics that are reported automatically by Lambda
    see also https://docs.aws.amazon.com/lambda/latest/dg/monitoring-metrics.html
    """

    @markers.aws.validated
    def test_lambda_invoke_successful(self, aws_client, create_lambda_function, snapshot):
        """
        successful invocation of lambda should report "Invocations" metric
        """
        fn_name = f"fn-cw-{short_uid()}"
        create_lambda_function(
            func_name=fn_name,
            handler_file=TEST_SUCCESSFUL_LAMBDA,
            runtime="python3.9",
        )
        result = aws_client.lambda_.invoke(FunctionName=fn_name)
        assert result["StatusCode"] == 200
        snapshot.match("invoke", result)

        # wait for metrics
        result = retry(
            lambda: self._wait_for_lambda_metric(
                aws_client.cloudwatch,
                fn_name=fn_name,
                metric_name="Invocations",
                expected_return=[1.0],
            ),
            retries=200 if is_aws() else 20,
            sleep=10 if is_aws() else 1,
        )
        snapshot.match("get-metric-data", result)

    @pytest.mark.skipif(not is_aws(), reason="'Errors' metrics not reported by LS")
    @markers.aws.validated
    def test_lambda_invoke_error(self, aws_client, create_lambda_function, snapshot):
        """
        Unsuccessful Invocation -> resulting in error, should report
        "Errors" and "Invocations" metrics
        """
        fn_name = f"fn-cw-{short_uid()}"
        create_lambda_function(
            func_name=fn_name,
            handler_file=TEST_FAILING_LAMBDA,
            runtime="python3.9",
        )
        result = aws_client.lambda_.invoke(FunctionName=fn_name)
        snapshot.match("invoke", result)

        # wait for metrics
        invocation_res = retry(
            lambda: self._wait_for_lambda_metric(
                aws_client.cloudwatch,
                fn_name=fn_name,
                metric_name="Invocations",
                expected_return=[1.0],
            ),
            retries=200 if is_aws() else 20,
            sleep=10 if is_aws() else 1,
        )
        snapshot.match("get-metric-data-invocations", invocation_res)

        # wait for "Errors"
        error_res = retry(
            lambda: self._wait_for_lambda_metric(
                aws_client.cloudwatch,
                fn_name=fn_name,
                metric_name="Errors",
                expected_return=[1.0],
            ),
            retries=200 if is_aws() else 20,
            sleep=10 if is_aws() else 1,
        )
        snapshot.match("get-metric-data-errors", error_res)

    def _wait_for_lambda_metric(
        self,
        cloudwatch_client: "CloudWatchClient",
        fn_name: str,
        metric_name: str,
        expected_return: list[float],
    ):
        namespace = "AWS/Lambda"
        dimension = [{"Name": "FunctionName", "Value": fn_name}]
        metric_query = {
            "Id": "m1",
            "MetricStat": {
                "Metric": {
                    "Namespace": namespace,
                    "MetricName": metric_name,
                    "Dimensions": dimension,
                },
                "Period": 3600,
                "Stat": "Sum",
            },
        }
        res = cloudwatch_client.get_metric_data(
            MetricDataQueries=[metric_query],
            StartTime=datetime.utcnow() - timedelta(hours=1),
            EndTime=datetime.utcnow(),
        )
        assert res["MetricDataResults"][0]["Values"] == expected_return
        return res
