import base64
import json

import pytest

from localstack.aws.api.lambda_ import Runtime
from localstack.utils.strings import short_uid, to_str
from localstack.utils.sync import retry
from tests.integration.awslambda.functions import lambda_integration
from tests.integration.awslambda.test_lambda import (
    TEST_LAMBDA_LIBS,
    TEST_LAMBDA_PYTHON,
    read_streams,
)


class TestLambdaDLQ:
    @pytest.mark.skip_snapshot_verify
    # @pytest.mark.aws_validated
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
            msg_attrs = result["Messages"][0]["MessageAttributes"]
            assert "RequestID" in msg_attrs
            assert "ErrorCode" in msg_attrs
            assert "ErrorMessage" in msg_attrs
            snapshot.match("sqs_dlq_message", result)

        # on AWS, event retries can be quite delayed, so we have to wait up to 6 minutes here, potential flakes
        retry(receive_dlq, retries=120, sleep=3)

        # update DLQ config
        update_function_config_response = lambda_client.update_function_configuration(
            FunctionName=lambda_name, DeadLetterConfig={}
        )
        snapshot.match("delete_dlq", update_function_config_response)
        # invoke Lambda again, assert that status code is 200 and error details contained in the payload
        result = lambda_client.invoke(
            FunctionName=lambda_name, Payload=json.dumps(payload), LogType="Tail"
        )
        result = read_streams(result)
        payload = json.loads(to_str(result["Payload"]))
        snapshot.match("result_payload", payload)
        assert 200 == result["StatusCode"]
        assert "Unhandled" == result["FunctionError"]
        assert "$LATEST" == result["ExecutedVersion"]
        assert "Test exception" in payload["errorMessage"]
        assert "Exception" in payload["errorType"]
        assert isinstance(payload["stackTrace"], list)
        log_result = result.get("LogResult")
        assert log_result
        logs = to_str(base64.b64decode(to_str(log_result)))
        assert "START" in logs
        assert "Test exception" in logs
        assert "END" in logs
        assert "REPORT" in logs


class TestLambdaDestinationSqs:
    @pytest.mark.parametrize(
        "condition,payload",
        [
            ("Success", {}),
            ("RetriesExhausted", {lambda_integration.MSG_BODY_RAISE_ERROR_FLAG: 1}),
        ],
    )
    @pytest.mark.skip_snapshot_verify
    # @pytest.mark.aws_validated
    def test_assess_lambda_destination_invocation(
        self,
        condition,
        payload,
        lambda_client,
        sqs_client,
        create_lambda_function,
        sqs_create_queue,
        sqs_queue_arn,
        lambda_su_role,
        snapshot,
    ):
        snapshot.add_transformer(snapshot.transform.lambda_api())
        snapshot.add_transformer(snapshot.transform.sqs_api())
        # message body contains ARN
        snapshot.add_transformer(snapshot.transform.key_value("MD5OfBody"))

        """Testing the destination config API and operation (for the OnSuccess case)"""
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
            msg = rs["Messages"][0]["Body"]
            msg = json.loads(msg)
            assert condition == msg["requestContext"]["condition"]
            snapshot.match("destination_message", rs)

        retry(receive_message, retries=120, sleep=3)


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
