import base64
import json
import os
import time
from typing import TYPE_CHECKING

import aws_cdk as cdk
import aws_cdk.aws_events as events
import aws_cdk.aws_events_targets as targets
import aws_cdk.aws_lambda as awslambda
import aws_cdk.aws_lambda_destinations as destinations
import aws_cdk.aws_sqs as sqs
import pytest
from aws_cdk.aws_events import EventPattern, Rule, RuleTargetInput
from aws_cdk.aws_lambda_event_sources import SqsEventSource

from localstack import config
from localstack.aws.api.lambda_ import Runtime
from localstack.testing.aws.util import is_aws_cloud
from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid, to_bytes, to_str
from localstack.utils.sync import retry, wait_until
from tests.aws.services.lambda_.functions import lambda_integration
from tests.aws.services.lambda_.test_lambda import TEST_LAMBDA_PYTHON

if TYPE_CHECKING:
    from mypy_boto3_s3 import CloudWatchLogsClient


class TestLambdaDLQ:
    @markers.snapshot.skip_snapshot_verify(
        paths=["$..DeadLetterConfig", "$..result", "$..LoggingConfig"]
    )
    @markers.aws.validated
    def test_dead_letter_queue(
        self,
        create_lambda_function,
        sqs_create_queue,
        sqs_get_queue_arn,
        lambda_su_role,
        snapshot,
        aws_client,
        monkeypatch,
    ):
        if not is_aws_cloud():
            monkeypatch.setattr(config, "LAMBDA_RETRY_BASE_DELAY_SECONDS", 5)

        """Creates a lambda with a defined dead letter queue, and check failed lambda invocation leads to a message"""
        # create DLQ and Lambda function
        snapshot.add_transformer(snapshot.transform.lambda_api())
        snapshot.add_transformer(snapshot.transform.sqs_api())
        snapshot.add_transformer(snapshot.transform.key_value("CodeSha256"))
        snapshot.add_transformer(snapshot.transform.key_value("MD5OfMessageAttributes"))
        snapshot.add_transformer(
            snapshot.transform.key_value("LogResult")
        )  # will be handled separately

        queue_name = f"test-{short_uid()}"
        lambda_name = f"test-{short_uid()}"
        queue_url = sqs_create_queue(QueueName=queue_name)
        queue_arn = sqs_get_queue_arn(queue_url)
        create_lambda_response = create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON,
            func_name=lambda_name,
            runtime=Runtime.python3_12,
            DeadLetterConfig={"TargetArn": queue_arn},
            role=lambda_su_role,
        )
        snapshot.match("create_lambda_with_dlq", create_lambda_response)

        # invoke Lambda, triggering an error
        payload = {lambda_integration.MSG_BODY_RAISE_ERROR_FLAG: 1}
        aws_client.lambda_.invoke(
            FunctionName=lambda_name,
            Payload=json.dumps(payload),
            InvocationType="Event",
        )

        # assert that message has been received on the DLQ
        def receive_dlq():
            result = aws_client.sqs.receive_message(
                QueueUrl=queue_url, MessageAttributeNames=["All"]
            )
            assert len(result["Messages"]) > 0
            return result

        # on AWS, event retries can be quite delayed, so we have to wait up to 6 minutes here, potential flakes
        receive_result = retry(receive_dlq, retries=120, sleep=3)
        snapshot.match("receive_result", receive_result)

        # update DLQ config
        update_function_config_response = aws_client.lambda_.update_function_configuration(
            FunctionName=lambda_name, DeadLetterConfig={}
        )
        snapshot.match("delete_dlq", update_function_config_response)
        # TODO: test function update with running invocation => don't kill them all in that case
        aws_client.lambda_.get_waiter("function_updated_v2").wait(FunctionName=lambda_name)
        invoke_result = aws_client.lambda_.invoke(
            FunctionName=lambda_name, Payload=json.dumps(payload), LogType="Tail"
        )
        snapshot.match("invoke_result", invoke_result)

        log_result = invoke_result["LogResult"]
        raw_logs = to_str(base64.b64decode(log_result))
        log_lines = raw_logs.splitlines()
        snapshot.match(
            "log_result",
            {"result": [line for line in log_lines if not line.startswith("REPORT")]},
        )


def wait_until_log_group_exists(fn_name: str, logs_client: "CloudWatchLogsClient"):
    def log_group_exists():
        return (
            len(
                logs_client.describe_log_groups(logGroupNamePrefix=f"/aws/lambda/{fn_name}")[
                    "logGroups"
                ]
            )
            == 1
        )

    wait_until(log_group_exists, max_retries=30 if is_aws_cloud() else 10)


class TestLambdaDestinationSqs:
    @pytest.mark.parametrize(
        "payload",
        [
            {},
            {lambda_integration.MSG_BODY_RAISE_ERROR_FLAG: 1},
        ],
    )
    @markers.aws.validated
    def test_assess_lambda_destination_invocation(
        self,
        payload,
        create_lambda_function,
        sqs_create_queue,
        sqs_get_queue_arn,
        lambda_su_role,
        snapshot,
        aws_client,
    ):
        """Testing the destination config API and operation (for the OnSuccess case)"""
        snapshot.add_transformer(snapshot.transform.lambda_api())
        snapshot.add_transformer(snapshot.transform.sqs_api())
        snapshot.add_transformer(snapshot.transform.key_value("MD5OfBody"))

        # create DLQ and Lambda function
        queue_name = f"test-{short_uid()}"
        lambda_name = f"test-{short_uid()}"
        queue_url = sqs_create_queue(QueueName=queue_name)
        queue_arn = sqs_get_queue_arn(queue_url)
        create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON,
            runtime=Runtime.python3_12,
            func_name=lambda_name,
            role=lambda_su_role,
        )

        put_event_invoke_config_response = aws_client.lambda_.put_function_event_invoke_config(
            FunctionName=lambda_name,
            MaximumRetryAttempts=0,
            DestinationConfig={
                "OnSuccess": {"Destination": queue_arn},
                "OnFailure": {"Destination": queue_arn},
            },
        )
        snapshot.match("put_function_event_invoke_config", put_event_invoke_config_response)

        aws_client.lambda_.invoke(
            FunctionName=lambda_name,
            Payload=json.dumps(payload),
            InvocationType="Event",
        )

        def receive_message():
            rs = aws_client.sqs.receive_message(
                QueueUrl=queue_url, WaitTimeSeconds=2, MessageAttributeNames=["All"]
            )
            assert len(rs["Messages"]) > 0
            return rs

        receive_message_result = retry(receive_message, retries=120, sleep=1)
        snapshot.match("receive_message_result", receive_message_result)

    @markers.aws.validated
    def test_lambda_destination_default_retries(
        self,
        create_lambda_function,
        sqs_create_queue,
        sqs_get_queue_arn,
        lambda_su_role,
        snapshot,
        monkeypatch,
        aws_client,
    ):
        snapshot.add_transformer(snapshot.transform.lambda_api())
        snapshot.add_transformer(snapshot.transform.sqs_api())
        snapshot.add_transformer(snapshot.transform.key_value("MD5OfBody"))

        if not is_aws_cloud():
            monkeypatch.setattr(config, "LAMBDA_RETRY_BASE_DELAY_SECONDS", 5)

        # create DLQ and Lambda function
        queue_name = f"test-{short_uid()}"
        lambda_name = f"test-{short_uid()}"
        queue_url = sqs_create_queue(QueueName=queue_name)
        queue_arn = sqs_get_queue_arn(queue_url)
        create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON,
            runtime=Runtime.python3_12,
            func_name=lambda_name,
            role=lambda_su_role,
        )

        put_event_invoke_config_response = aws_client.lambda_.put_function_event_invoke_config(
            FunctionName=lambda_name,
            DestinationConfig={
                "OnSuccess": {"Destination": queue_arn},
                "OnFailure": {"Destination": queue_arn},
            },
        )
        snapshot.match("put_function_event_invoke_config", put_event_invoke_config_response)

        aws_client.lambda_.invoke(
            FunctionName=lambda_name,
            Payload=json.dumps({lambda_integration.MSG_BODY_RAISE_ERROR_FLAG: 1}),
            InvocationType="Event",
        )

        def receive_message():
            rs = aws_client.sqs.receive_message(
                QueueUrl=queue_url, WaitTimeSeconds=2, MessageAttributeNames=["All"]
            )
            assert len(rs["Messages"]) > 0
            return rs

        # this will take at least 3 minutes on AWS
        receive_message_result = retry(receive_message, retries=120, sleep=3)
        snapshot.match("receive_message_result", receive_message_result)

    @markers.snapshot.skip_snapshot_verify(paths=["$..Body.requestContext.functionArn"])
    @markers.aws.validated
    def test_retries(
        self,
        snapshot,
        create_lambda_function,
        sqs_create_queue,
        sqs_get_queue_arn,
        lambda_su_role,
        monkeypatch,
        aws_client,
    ):
        """
        behavior test, we don't really care about any API surface here right now

        this is quite long since lambda waits 1 minute between the invoke and first retry and 2 minutes between the first retry and the second retry!
        TODO: test if invocation/request ID changes between retries
        """
        snapshot.add_transformer(snapshot.transform.lambda_api())
        snapshot.add_transformer(snapshot.transform.sqs_api())
        snapshot.add_transformer(
            snapshot.transform.key_value(
                "MD5OfBody", value_replacement="<md5-body>", reference_replacement=False
            )
        )

        test_delay_base = 60
        if not is_aws_cloud():
            test_delay_base = 5
            monkeypatch.setattr(config, "LAMBDA_RETRY_BASE_DELAY_SECONDS", test_delay_base)

        # setup
        queue_name = f"destination-queue-{short_uid()}"
        fn_name = f"retry-fn-{short_uid()}"
        message_id = f"retry-msg-{short_uid()}"
        snapshot.add_transformer(snapshot.transform.regex(message_id, "<test-msg-id>"))

        queue_url = sqs_create_queue(QueueName=queue_name)
        queue_arn = sqs_get_queue_arn(queue_url)

        create_lambda_function(
            handler_file=os.path.join(os.path.dirname(__file__), "functions/lambda_echofail.py"),
            func_name=fn_name,
            runtime=Runtime.python3_12,
            role=lambda_su_role,
        )
        aws_client.lambda_.put_function_event_invoke_config(
            FunctionName=fn_name,
            MaximumRetryAttempts=2,
            DestinationConfig={"OnFailure": {"Destination": queue_arn}},
        )
        aws_client.lambda_.get_waiter("function_updated_v2").wait(FunctionName=fn_name)

        invoke_result = aws_client.lambda_.invoke(
            FunctionName=fn_name,
            Payload=to_bytes(json.dumps({"message": message_id})),
            InvocationType="Event",  # important, otherwise destinations won't be triggered
        )
        assert 200 <= invoke_result["StatusCode"] < 300

        def get_filtered_event_count() -> int:
            filter_result = retry(
                aws_client.logs.filter_log_events, sleep=2.0, logGroupName=f"/aws/lambda/{fn_name}"
            )
            filtered_log_events = [e for e in filter_result["events"] if message_id in e["message"]]
            return len(filtered_log_events)

        # between 0 and 1 min the lambda should NOT have been retried yet
        # between 1 min and 3 min the lambda should have been retried once
        # TODO: parse log and calculate time diffs for better/more reliable matching
        # SQS queue has a thread checking every second, hence we need a 1 second offset
        test_delay_base_with_offset = test_delay_base + 1
        time.sleep(test_delay_base_with_offset / 2)
        assert get_filtered_event_count() == 1
        time.sleep(test_delay_base_with_offset)
        assert get_filtered_event_count() == 2
        time.sleep(test_delay_base_with_offset * 2)
        assert get_filtered_event_count() == 3

        # 1. event should be in queue
        def msg_in_queue():
            msgs = aws_client.sqs.receive_message(
                QueueUrl=queue_url, AttributeNames=["All"], VisibilityTimeout=0
            )
            return len(msgs["Messages"]) == 1

        assert wait_until(msg_in_queue)

        # We didn't delete the message so it should be available again after waiting shortly (2x visibility timeout to be sure)
        msgs = aws_client.sqs.receive_message(
            QueueUrl=queue_url, AttributeNames=["All"], VisibilityTimeout=1
        )
        snapshot.match("queue_destination_payload", msgs)

        # 2. there should be only one event stream (re-use of environment)
        #    technically not guaranteed but should be nearly 100%
        log_streams = aws_client.logs.describe_log_streams(logGroupName=f"/aws/lambda/{fn_name}")
        assert len(log_streams["logStreams"]) == 1

        # 3. the lambda should have been called 3 times (correlation via custom message id)
        assert get_filtered_event_count() == 3

        # verify the event ID is the same in all calls
        log_events = aws_client.logs.filter_log_events(logGroupName=f"/aws/lambda/{fn_name}")[
            "events"
        ]

        # only get messages with the printed event
        request_ids = [
            json.loads(e["message"])["aws_request_id"]
            for e in log_events
            if message_id in e["message"]
        ]

        assert len(request_ids) == 3  # gather invocation ID from all 3 invocations
        assert len(set(request_ids)) == 1  # all 3 are equal

    @markers.snapshot.skip_snapshot_verify(
        paths=["$..SenderId", "$..Body.requestContext.functionArn"]
    )
    @markers.aws.validated
    def test_maxeventage(
        self,
        snapshot,
        create_lambda_function,
        sqs_create_queue,
        sqs_get_queue_arn,
        lambda_su_role,
        monkeypatch,
        aws_client,
    ):
        """
        Behavior test for MaximumRetryAttempts in EventInvokeConfig

        Noteworthy observation:
        * lambda doesn't even wait for the full 60s before the OnFailure destination / DLQ is triggered

        """
        snapshot.add_transformer(snapshot.transform.lambda_api())
        snapshot.add_transformer(snapshot.transform.sqs_api())
        snapshot.add_transformer(
            snapshot.transform.key_value(
                "MD5OfBody", value_replacement="<md5-body>", reference_replacement=False
            )
        )

        queue_name = f"destination-queue-{short_uid()}"
        fn_name = f"retry-fn-{short_uid()}"
        message_id = f"retry-msg-{short_uid()}"
        snapshot.add_transformer(snapshot.transform.regex(message_id, "<test-msg-id>"))
        queue_url = sqs_create_queue(QueueName=queue_name)
        queue_arn = sqs_get_queue_arn(queue_url)

        create_lambda_function(
            handler_file=os.path.join(os.path.dirname(__file__), "functions/lambda_echofail.py"),
            func_name=fn_name,
            role=lambda_su_role,
        )
        aws_client.lambda_.put_function_event_invoke_config(
            FunctionName=fn_name,
            MaximumRetryAttempts=2,
            MaximumEventAgeInSeconds=60,
            DestinationConfig={"OnFailure": {"Destination": queue_arn}},
        )
        aws_client.lambda_.get_waiter("function_updated_v2").wait(FunctionName=fn_name)

        aws_client.lambda_.invoke(
            FunctionName=fn_name,
            Payload=to_bytes(json.dumps({"message": message_id})),
            InvocationType="Event",  # important, otherwise destinations won't be triggered
        )

        # wait for log group to exist

        wait_until_log_group_exists(fn_name, aws_client.logs)

        def get_filtered_event_count() -> int:
            filter_result = retry(
                aws_client.logs.filter_log_events, sleep=2.0, logGroupName=f"/aws/lambda/{fn_name}"
            )
            filtered_log_events = [e for e in filter_result["events"] if message_id in e["message"]]
            return len(filtered_log_events)

        # lambda doesn't retry because the first delay already is 60s
        # invocation + 60s (1st delay) > 60s (configured max)

        def get_msg_from_q():
            msgs = aws_client.sqs.receive_message(
                QueueUrl=queue_url,
                AttributeNames=["All"],
                VisibilityTimeout=3,
                MaxNumberOfMessages=1,
                WaitTimeSeconds=5,
            )
            assert len(msgs["Messages"]) == 1
            aws_client.sqs.delete_message(
                QueueUrl=queue_url, ReceiptHandle=msgs["Messages"][0]["ReceiptHandle"]
            )
            return msgs["Messages"][0]

        msg = retry(get_msg_from_q, retries=15, sleep=3)
        snapshot.match("no_retry_failure_message", msg)

        def _assert_event_count(count: int):
            assert get_filtered_event_count() == count

        retry(_assert_event_count, retries=5, sleep=1, count=1)  # 1 attempt in total (no retries)

        # now we increase the max event age to give it a bit of a buffer for the actual lambda execution (60s + 30s buffer = 90s)
        # one retry should now be attempted since there's enough time left
        aws_client.lambda_.update_function_event_invoke_config(
            FunctionName=fn_name, MaximumEventAgeInSeconds=90, MaximumRetryAttempts=2
        )
        aws_client.lambda_.get_waiter("function_updated_v2").wait(FunctionName=fn_name)

        # deleting the log group, so we have a 'fresh' counter
        # without it, the assertion later would need to accommodate for previous invocations
        aws_client.logs.delete_log_group(logGroupName=f"/aws/lambda/{fn_name}")

        aws_client.lambda_.invoke(
            FunctionName=fn_name,
            Payload=to_bytes(json.dumps({"message": message_id})),
            InvocationType="Event",  # important, otherwise destinations won't be triggered
        )
        time.sleep(
            60
        )  # absolute minimum wait time (time lambda waits between invoke and first retry)

        msg_retried = retry(get_msg_from_q, retries=15, sleep=3)
        snapshot.match("single_retry_failure_message", msg_retried)

        retry(_assert_event_count, retries=5, sleep=1, count=2)  # 2 attempts in total (1 retry)


# class TestLambdaDestinationSns:
#     ...  # TODO
#
#
# class TestLambdaDestinationLambda:
#     ...  # TODO
#
#
class TestLambdaDestinationEventbridge:
    EVENT_BRIDGE_STACK = "EventbridgeStack"
    INPUT_FUNCTION_NAME = "InputFunc"
    TRIGGERED_FUNCTION_NAME = "TriggeredFunc"
    TEST_QUEUE_NAME = "TestQueueName"

    INPUT_LAMBDA_CODE = """
def handler(event, context):
    return {
            "hello": "world",
            "test": "abc",
            "val": 5,
            "success": True
        }
"""
    TRIGGERED_LAMBDA_CODE = """
import json

def handler(event, context):
    print(json.dumps(event))
    return {"invocation": True}
"""

    @pytest.fixture(scope="class", autouse=True)
    def infrastructure(self, aws_client, infrastructure_setup):
        infra = infrastructure_setup(namespace="LambdaDestinationEventbridge")
        input_fn_name = f"input-fn-{short_uid()}"
        triggered_fn_name = f"triggered-fn-{short_uid()}"

        # setup a stack with two lambdas:
        #  - input-lambda will be invoked manually
        #      - its output is written to SQS queue by using an EventBridge
        #  - triggered lambda invoked by SQS event source
        stack = cdk.Stack(infra.cdk_app, self.EVENT_BRIDGE_STACK)
        event_bus = events.EventBus(
            stack, "MortgageQuotesEventBus", event_bus_name="MortgageQuotesEventBus"
        )

        test_queue = sqs.Queue(
            stack,
            "TestQueue",
            retention_period=cdk.Duration.minutes(5),
            removal_policy=cdk.RemovalPolicy.DESTROY,
        )

        message_filter_rule = Rule(
            stack,
            "EmptyFilterRule",
            event_bus=event_bus,
            rule_name="CustomRule",
            event_pattern=EventPattern(version=["0"]),
        )

        message_filter_rule.add_target(
            targets.SqsQueue(
                queue=test_queue,
                message=RuleTargetInput.from_event_path("$.detail.responsePayload"),
            )
        )

        input_func = awslambda.Function(
            stack,
            "InputLambda",
            runtime=awslambda.Runtime.PYTHON_3_10,
            handler="index.handler",
            code=awslambda.InlineCode(code=self.INPUT_LAMBDA_CODE),
            function_name=input_fn_name,
            on_success=destinations.EventBridgeDestination(event_bus=event_bus),
        )

        triggered_func = awslambda.Function(
            stack,
            "TriggeredLambda",
            runtime=awslambda.Runtime.PYTHON_3_10,
            code=awslambda.InlineCode(code=self.TRIGGERED_LAMBDA_CODE),
            handler="index.handler",
            function_name=triggered_fn_name,
        )

        triggered_func.add_event_source(SqsEventSource(test_queue, batch_size=10))

        cdk.CfnOutput(stack, self.INPUT_FUNCTION_NAME, value=input_func.function_name)
        cdk.CfnOutput(stack, self.TRIGGERED_FUNCTION_NAME, value=triggered_func.function_name)
        cdk.CfnOutput(stack, self.TEST_QUEUE_NAME, value=test_queue.queue_name)

        with infra.provisioner(skip_teardown=False) as prov:
            yield prov

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(paths=["$..AWSTraceHeader", "$..SenderId"])
    def test_invoke_lambda_eventbridge(self, infrastructure, aws_client, snapshot):
        outputs = infrastructure.get_stack_outputs(self.EVENT_BRIDGE_STACK)
        input_fn_name = outputs.get(self.INPUT_FUNCTION_NAME)
        triggered_fn_name = outputs.get(self.TRIGGERED_FUNCTION_NAME)
        test_queue_name = outputs.get(self.TEST_QUEUE_NAME)

        snapshot.add_transformer(snapshot.transform.key_value("messageId"))
        snapshot.add_transformer(snapshot.transform.key_value("receiptHandle"))
        snapshot.add_transformer(
            snapshot.transform.key_value("SenderId"), priority=2
        )  # TODO currently on LS sender-id == account-id -> replaces part of the eventSourceARN without the priority
        snapshot.add_transformer(
            snapshot.transform.key_value(
                "AWSTraceHeader", "trace-header", reference_replacement=False
            )
        )
        snapshot.add_transformer(
            snapshot.transform.key_value("md5OfBody", reference_replacement=False)
        )
        snapshot.add_transformer(snapshot.transform.regex(test_queue_name, "TestQueue"))

        aws_client.lambda_.invoke(
            FunctionName=input_fn_name,
            Payload=b"{}",
            InvocationType="Event",  # important, otherwise destinations won't be triggered
        )
        # wait until triggered lambda was invoked
        wait_until_log_group_exists(triggered_fn_name, aws_client.logs)

        def _filter_message_triggered():
            log_events = aws_client.logs.filter_log_events(
                logGroupName=f"/aws/lambda/{triggered_fn_name}"
            )["events"]
            filtered_logs = [event for event in log_events if event["message"].startswith("{")]
            assert len(filtered_logs) >= 1
            filtered_logs.sort(key=lambda e: e["timestamp"], reverse=True)
            return filtered_logs[0]

        log = retry(_filter_message_triggered, retries=50 if is_aws_cloud() else 10)
        snapshot.match("filtered_message_event_bus_sqs", log["message"])
