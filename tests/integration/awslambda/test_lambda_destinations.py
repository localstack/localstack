import base64
import json

import pytest

from localstack.aws.api.lambda_ import Runtime
from localstack.testing.aws.lambda_utils import is_new_provider, is_old_provider
from localstack.utils.strings import short_uid, to_str
from localstack.utils.sync import retry
from tests.integration.awslambda.functions import lambda_integration
from tests.integration.awslambda.test_lambda import TEST_LAMBDA_LIBS, TEST_LAMBDA_PYTHON


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
            libs=TEST_LAMBDA_LIBS,
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
        ],
    )
    @pytest.mark.skip_snapshot_verify(
        condition=is_new_provider,
        paths=[
            "$..approximateInvokeCount",  # TODO: retry support
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
            func_name=lambda_name,
            libs=TEST_LAMBDA_LIBS,
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
            Payload=json.dumps(payload),
            InvocationType="Event",
        )

        def receive_message():
            rs = sqs_client.receive_message(QueueUrl=queue_url, MessageAttributeNames=["All"])
            assert len(rs["Messages"]) > 0
            return rs

        receive_message_result = retry(receive_message, retries=120, sleep=3)
        snapshot.match("receive_message_result", receive_message_result)


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
