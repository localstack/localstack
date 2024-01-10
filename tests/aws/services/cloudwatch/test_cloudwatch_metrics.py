import json
from datetime import datetime, timedelta
from typing import TYPE_CHECKING

from localstack.testing.pytest import markers
from localstack.testing.pytest.snapshot import is_aws
from localstack.utils.aws.arns import extract_resource_from_arn
from localstack.utils.strings import short_uid
from tests.aws.services.cloudwatch.test_cloudwatch import get_sqs_policy

if TYPE_CHECKING:
    from mypy_boto3_cloudwatch import CloudWatchClient
    from mypy_boto3_sqs import SQSClient
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


class TestSqsApproximateMetrics:
    @markers.aws.validated
    def test_sqs_approximate_metrics(self, aws_client, sqs_create_queue):
        queue_names = []
        for _ in range(0, 10):
            q_name = f"my-test-queue-{short_uid()}"
            sqs_create_queue(QueueName=q_name)
            queue_names.append(q_name)

        for queue in queue_names:
            retry(
                lambda: self._assert_approximate_metrics_for_queue(
                    aws_client.cloudwatch, queue_name=queue
                ),
                retries=70,  # should be reported every 60 seconds on LS
                sleep=10 if is_aws() else 1,
            )

    def _assert_approximate_metrics_for_queue(
        self,
        cloudwatch_client: "CloudWatchClient",
        queue_name: str,
    ):
        namespace = "AWS/SQS"
        dimension = [{"Name": "QueueName", "Value": queue_name}]

        res = cloudwatch_client.list_metrics(Namespace=namespace, Dimensions=dimension)
        metric_names = [m["MetricName"] for m in res["Metrics"]]
        assert "ApproximateNumberOfMessagesVisible" in metric_names
        assert "ApproximateNumberOfMessagesNotVisible" in metric_names
        assert "ApproximateNumberOfMessagesDelayed" in metric_names
        return res


class TestSQSMetrics:
    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            "$..MetricAlarms..StateReason",
            "$..MetricAlarms..StateReasonData.evaluatedDatapoints",
            "$..MetricAlarms..StateReasonData.startDate",
            "$..MetricAlarms..StateTransitionedTimestamp",
            "$..NewStateReason",
        ]
    )
    def test_alarm_number_of_messages_sent(
        self, aws_client, sns_create_topic, sqs_create_queue, cleanups, snapshot
    ):
        snapshot.add_transformer(snapshot.transform.cloudwatch_api())
        # transform the date, that is part of the StateReason
        #  eg. "Threshold Crossed: 1 datapoint [1.0 (03/01/24 11:36:00)] was greater than the threshold (0.0).",
        snapshot.add_transformer(
            # regex to transform date-pattern, e.g. (03/01/24 11:36:00)
            snapshot.transform.regex(
                r"\(\d{2}\/\d{2}\/\d{2}\ \d{2}:\d{2}:\d{2}\)", "(MM/DD/YY HH:MM:SS)"
            )
        )
        # sns topic -> will be notified by alarm
        sns_topic_alarm = sns_create_topic()
        topic_arn_alarm = sns_topic_alarm["TopicArn"]
        snapshot.add_transformer(
            snapshot.transform.regex(extract_resource_from_arn(topic_arn_alarm), "<topic-name>")
        )

        # sqs queue will subscribe to sns topic
        # -> so we can check the alarm action was triggered
        sqs_url_alarm_triggered_check = sqs_create_queue()
        sqs_arn_alarm_triggered = aws_client.sqs.get_queue_attributes(
            QueueUrl=sqs_url_alarm_triggered_check, AttributeNames=["QueueArn"]
        )["Attributes"]["QueueArn"]
        # set policy - required for AWS:
        aws_client.sqs.set_queue_attributes(
            QueueUrl=sqs_url_alarm_triggered_check,
            Attributes={"Policy": get_sqs_policy(sqs_arn_alarm_triggered, topic_arn_alarm)},
        )
        # add subscription
        subscription = aws_client.sns.subscribe(
            TopicArn=topic_arn_alarm, Protocol="sqs", Endpoint=sqs_arn_alarm_triggered
        )
        cleanups.append(
            lambda: aws_client.sns.unsubscribe(SubscriptionArn=subscription["SubscriptionArn"])
        )
        queue_name = f"queue-to-watch-{short_uid()}"
        snapshot.add_transformer(snapshot.transform.regex(queue_name, "<replaced-queue-name>"))

        alarm_name = f"check_sqs_messages_{short_uid()}"
        aws_client.cloudwatch.put_metric_alarm(
            AlarmName=alarm_name,
            AlarmDescription="test messages sent",
            MetricName="NumberOfMessagesSent",
            Namespace="AWS/SQS",
            ActionsEnabled=True,
            Period=60,
            Threshold=0,
            Dimensions=[{"Name": "QueueName", "Value": queue_name}],
            Statistic="SampleCount",
            OKActions=[],
            AlarmActions=[topic_arn_alarm],
            EvaluationPeriods=1,
            ComparisonOperator="GreaterThanThreshold",
            TreatMissingData="missing",
        )
        cleanups.append(lambda: aws_client.cloudwatch.delete_alarms(AlarmNames=[alarm_name]))

        # create the sqs test queue, where we will manually send a message to
        # and will set an alarm specific for that queue
        # it should automatically report the metric "NumberOfMessagesSent"
        sqs_test_queue_url = sqs_create_queue(QueueName=queue_name)
        aws_client.sqs.send_message(QueueUrl=sqs_test_queue_url, MessageBody="new message")

        retry(
            self._verify_alarm_triggered,
            retries=60,
            sleep=3 if is_aws() else 1,
            cloudwatch_client=aws_client.cloudwatch,
            sqs_client=aws_client.sqs,
            alarm_name=alarm_name,
            sqs_queue_url=sqs_url_alarm_triggered_check,
            identifier="NumberOfMessagesSent",
            snapshot=snapshot,
        )

    def _verify_alarm_triggered(
        self,
        cloudwatch_client: "CloudWatchClient",
        sqs_client: "SQSClient",
        alarm_name: str,
        sqs_queue_url: str,
        identifier: str,
        snapshot,
    ):
        response = cloudwatch_client.describe_alarms(AlarmNames=[alarm_name])
        assert response["MetricAlarms"][0]["StateValue"] == "ALARM"

        result = sqs_client.receive_message(QueueUrl=sqs_queue_url, VisibilityTimeout=0)
        msg = result["Messages"][0]
        body = json.loads(msg["Body"])
        message = json.loads(body["Message"])
        sqs_client.delete_message(QueueUrl=sqs_queue_url, ReceiptHandle=msg["ReceiptHandle"])
        assert message["NewStateValue"] == "ALARM"
        snapshot.match(f"{identifier}-describe", response)
        snapshot.match(f"{identifier}-sqs-msg", message)
