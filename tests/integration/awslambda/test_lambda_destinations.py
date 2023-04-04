import base64
import json
import os
import time

import pytest

from localstack import config
from localstack.aws.api.lambda_ import Runtime
from localstack.testing.aws.lambda_utils import is_old_provider
from localstack.testing.aws.util import is_aws_cloud
from localstack.utils.strings import short_uid, to_bytes, to_str
from localstack.utils.sync import retry, wait_until
from tests.integration.awslambda.functions import lambda_integration
from tests.integration.awslambda.test_lambda import TEST_LAMBDA_PYTHON


class TestLambdaDLQ:
    @pytest.mark.skip_snapshot_verify(paths=["$..DeadLetterConfig", "$..result"])
    @pytest.mark.skip_snapshot_verify(
        condition=is_old_provider,
    )
    @pytest.mark.aws_validated
    def test_dead_letter_queue(
        self,
        lambda_client,
        create_lambda_function,
        sqs_client,
        sqs_create_queue,
        sqs_queue_arn,
        lambda_su_role,
        snapshot,
    ):
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
        queue_arn = sqs_queue_arn(queue_url)
        create_lambda_response = create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON,
            func_name=lambda_name,
            runtime=Runtime.python3_9,
            DeadLetterConfig={"TargetArn": queue_arn},
            role=lambda_su_role,
        )
        snapshot.match("create_lambda_with_dlq", create_lambda_response)

        # invoke Lambda, triggering an error
        payload = {lambda_integration.MSG_BODY_RAISE_ERROR_FLAG: 1}
        lambda_client.invoke(
            FunctionName=lambda_name,
            Payload=json.dumps(payload),
            InvocationType="Event",
        )

        # assert that message has been received on the DLQ
        def receive_dlq():
            result = sqs_client.receive_message(QueueUrl=queue_url, MessageAttributeNames=["All"])
            assert len(result["Messages"]) > 0
            return result

        # on AWS, event retries can be quite delayed, so we have to wait up to 6 minutes here, potential flakes
        receive_result = retry(receive_dlq, retries=120, sleep=3)
        snapshot.match("receive_result", receive_result)

        # update DLQ config
        update_function_config_response = lambda_client.update_function_configuration(
            FunctionName=lambda_name, DeadLetterConfig={}
        )
        snapshot.match("delete_dlq", update_function_config_response)
        invoke_result = lambda_client.invoke(
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


class TestLambdaDestinationSqs:
    @pytest.mark.skip_snapshot_verify(
        condition=is_old_provider,
        paths=[
            "$..context",
            "$..MessageId",
            "$..functionArn",
            "$..FunctionArn",
            "$..approximateInvokeCount",
            "$..stackTrace",
            "$..Messages..Body.responsePayload.requestId",
        ],
    )
    @pytest.mark.parametrize(
        "payload",
        [
            {},
            {lambda_integration.MSG_BODY_RAISE_ERROR_FLAG: 1},
        ],
    )
    @pytest.mark.aws_validated
    def test_assess_lambda_destination_invocation(
        self,
        payload,
        lambda_client,
        sqs_client,
        create_lambda_function,
        sqs_create_queue,
        sqs_queue_arn,
        lambda_su_role,
        snapshot,
    ):
        """Testing the destination config API and operation (for the OnSuccess case)"""
        snapshot.add_transformer(snapshot.transform.lambda_api())
        snapshot.add_transformer(snapshot.transform.sqs_api())
        snapshot.add_transformer(snapshot.transform.key_value("MD5OfBody"))

        # create DLQ and Lambda function
        queue_name = f"test-{short_uid()}"
        lambda_name = f"test-{short_uid()}"
        queue_url = sqs_create_queue(QueueName=queue_name)
        queue_arn = sqs_queue_arn(queue_url)
        create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON,
            runtime=Runtime.python3_9,
            func_name=lambda_name,
            role=lambda_su_role,
        )

        put_event_invoke_config_response = lambda_client.put_function_event_invoke_config(
            FunctionName=lambda_name,
            MaximumRetryAttempts=0,
            DestinationConfig={
                "OnSuccess": {"Destination": queue_arn},
                "OnFailure": {"Destination": queue_arn},
            },
        )
        snapshot.match("put_function_event_invoke_config", put_event_invoke_config_response)

        lambda_client.invoke(
            FunctionName=lambda_name,
            Payload=json.dumps(payload),
            InvocationType="Event",
        )

        def receive_message():
            rs = sqs_client.receive_message(
                QueueUrl=queue_url, WaitTimeSeconds=2, MessageAttributeNames=["All"]
            )
            assert len(rs["Messages"]) > 0
            return rs

        receive_message_result = retry(receive_message, retries=120, sleep=1)
        snapshot.match("receive_message_result", receive_message_result)

    @pytest.mark.skipif(
        condition=is_old_provider(), reason="config variable only supported in new provider"
    )
    def test_lambda_destination_default_retries(
        self,
        lambda_client,
        sqs_client,
        create_lambda_function,
        sqs_create_queue,
        sqs_queue_arn,
        lambda_su_role,
        snapshot,
        monkeypatch,
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
        queue_arn = sqs_queue_arn(queue_url)
        create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON,
            runtime=Runtime.python3_9,
            func_name=lambda_name,
            role=lambda_su_role,
        )

        put_event_invoke_config_response = lambda_client.put_function_event_invoke_config(
            FunctionName=lambda_name,
            DestinationConfig={
                "OnSuccess": {"Destination": queue_arn},
                "OnFailure": {"Destination": queue_arn},
            },
        )
        snapshot.match("put_function_event_invoke_config", put_event_invoke_config_response)

        lambda_client.invoke(
            FunctionName=lambda_name,
            Payload=json.dumps({lambda_integration.MSG_BODY_RAISE_ERROR_FLAG: 1}),
            InvocationType="Event",
        )

        def receive_message():
            rs = sqs_client.receive_message(
                QueueUrl=queue_url, WaitTimeSeconds=2, MessageAttributeNames=["All"]
            )
            assert len(rs["Messages"]) > 0
            return rs

        # this will take at least 3 minutes on AWS
        receive_message_result = retry(receive_message, retries=120, sleep=3)
        snapshot.match("receive_message_result", receive_message_result)

    @pytest.mark.skip_snapshot_verify(paths=["$..Body.requestContext.functionArn"])
    @pytest.mark.xfail(condition=is_old_provider(), reason="only works with new provider")
    @pytest.mark.aws_validated
    def test_retries(
        self,
        lambda_client,
        snapshot,
        create_lambda_function,
        sqs_create_queue,
        sqs_queue_arn,
        lambda_su_role,
        logs_client,
        sqs_client,
        monkeypatch,
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
        queue_arn = sqs_queue_arn(queue_url)

        create_lambda_function(
            handler_file=os.path.join(os.path.dirname(__file__), "./functions/lambda_echofail.py"),
            func_name=fn_name,
            runtime=Runtime.python3_9,
            role=lambda_su_role,
        )
        lambda_client.put_function_event_invoke_config(
            FunctionName=fn_name,
            MaximumRetryAttempts=2,
            DestinationConfig={"OnFailure": {"Destination": queue_arn}},
        )
        lambda_client.get_waiter("function_updated_v2").wait(FunctionName=fn_name)

        invoke_result = lambda_client.invoke(
            FunctionName=fn_name,
            Payload=to_bytes(json.dumps({"message": message_id})),
            InvocationType="Event",  # important, otherwise destinations won't be triggered
        )
        assert 200 <= invoke_result["StatusCode"] < 300

        def get_filtered_event_count() -> int:
            filter_result = retry(
                logs_client.filter_log_events, sleep=2.0, logGroupName=f"/aws/lambda/{fn_name}"
            )
            filtered_log_events = [e for e in filter_result["events"] if message_id in e["message"]]
            return len(filtered_log_events)

        # between 0 and 1 min the lambda should NOT have been retried yet
        # between 1 min and 3 min the lambda should have been retried once
        time.sleep(test_delay_base / 2)
        assert get_filtered_event_count() == 1
        time.sleep(test_delay_base)
        assert get_filtered_event_count() == 2
        time.sleep(test_delay_base * 2)
        assert get_filtered_event_count() == 3

        # 1. event should be in queue
        def msg_in_queue():
            msgs = sqs_client.receive_message(
                QueueUrl=queue_url, AttributeNames=["All"], VisibilityTimeout=0
            )
            return len(msgs["Messages"]) == 1

        assert wait_until(msg_in_queue)

        # We didn't delete the message so it should be available again after waiting shortly (2x visibility timeout to be sure)
        msgs = sqs_client.receive_message(
            QueueUrl=queue_url, AttributeNames=["All"], VisibilityTimeout=1
        )
        snapshot.match("queue_destination_payload", msgs)

        # 2. there should be only one event stream (re-use of environment)
        #    technically not guaranteed but should be nearly 100%
        log_streams = logs_client.describe_log_streams(logGroupName=f"/aws/lambda/{fn_name}")
        assert len(log_streams["logStreams"]) == 1

        # 3. the lambda should have been called 3 times (correlation via custom message id)
        assert get_filtered_event_count() == 3

        # verify the event ID is the same in all calls
        log_events = logs_client.filter_log_events(logGroupName=f"/aws/lambda/{fn_name}")["events"]

        # only get messages with the printed event
        request_ids = [
            json.loads(e["message"])["aws_request_id"]
            for e in log_events
            if message_id in e["message"]
        ]

        assert len(request_ids) == 3  # gather invocation ID from all 3 invocations
        assert len(set(request_ids)) == 1  # all 3 are equal

    @pytest.mark.skip_snapshot_verify(paths=["$..SenderId", "$..Body.requestContext.functionArn"])
    @pytest.mark.xfail(condition=is_old_provider(), reason="only works with new provider")
    @pytest.mark.aws_validated
    def test_maxeventage(
        self,
        lambda_client,
        snapshot,
        create_lambda_function,
        sqs_create_queue,
        sqs_queue_arn,
        lambda_su_role,
        logs_client,
        sqs_client,
        monkeypatch,
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
        queue_arn = sqs_queue_arn(queue_url)

        create_lambda_function(
            handler_file=os.path.join(os.path.dirname(__file__), "./functions/lambda_echofail.py"),
            func_name=fn_name,
            role=lambda_su_role,
        )
        lambda_client.put_function_event_invoke_config(
            FunctionName=fn_name,
            MaximumRetryAttempts=2,
            MaximumEventAgeInSeconds=60,
            DestinationConfig={"OnFailure": {"Destination": queue_arn}},
        )
        lambda_client.get_waiter("function_updated_v2").wait(FunctionName=fn_name)

        lambda_client.invoke(
            FunctionName=fn_name,
            Payload=to_bytes(json.dumps({"message": message_id})),
            InvocationType="Event",  # important, otherwise destinations won't be triggered
        )

        # wait for log group to exist
        def log_group_exists():
            return (
                len(
                    logs_client.describe_log_groups(logGroupNamePrefix=f"/aws/lambda/{fn_name}")[
                        "logGroups"
                    ]
                )
                == 1
            )

        wait_until(log_group_exists)

        def get_filtered_event_count() -> int:
            filter_result = retry(
                logs_client.filter_log_events, sleep=2.0, logGroupName=f"/aws/lambda/{fn_name}"
            )
            filtered_log_events = [e for e in filter_result["events"] if message_id in e["message"]]
            return len(filtered_log_events)

        # lambda doesn't retry because the first delay already is 60s
        # invocation + 60s (1st delay) > 60s (configured max)

        def get_msg_from_q():
            msgs = sqs_client.receive_message(
                QueueUrl=queue_url,
                AttributeNames=["All"],
                VisibilityTimeout=3,
                MaxNumberOfMessages=1,
                WaitTimeSeconds=5,
            )
            assert len(msgs["Messages"]) == 1
            sqs_client.delete_message(
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
        lambda_client.update_function_event_invoke_config(
            FunctionName=fn_name, MaximumEventAgeInSeconds=90, MaximumRetryAttempts=2
        )
        lambda_client.get_waiter("function_updated_v2").wait(FunctionName=fn_name)

        # deleting the log group, so we have a 'fresh' counter
        # without it, the assertion later would need to accommodate for previous invocations
        logs_client.delete_log_group(logGroupName=f"/aws/lambda/{fn_name}")

        lambda_client.invoke(
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
# class TestLambdaDestinationEventbridge:
#     ...  # TODO
