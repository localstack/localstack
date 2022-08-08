import json
import os
import time

import pytest

from localstack.services.awslambda.lambda_utils import LAMBDA_RUNTIME_PYTHON38
from localstack.utils.strings import short_uid
from localstack.utils.sync import retry

THIS_FOLDER = os.path.dirname(os.path.realpath(__file__))
LAMBDA_SQS_INTEGRATION_FILE = os.path.join(THIS_FOLDER, "functions", "lambda_sqs_integration.py")


def _await_event_source_mapping_enabled(lambda_client, uuid, retries=30):
    def assert_mapping_enabled():
        assert lambda_client.get_event_source_mapping(UUID=uuid)["State"] == "Enabled"

    retry(assert_mapping_enabled, sleep_before=2, retries=retries)


@pytest.fixture(autouse=True)
def _snapshot_transformers(snapshot):
    # manual transformers since we are passing SQS attributes through lambdas and back again
    snapshot.add_transformer(snapshot.transform.key_value("QueueUrl"))
    snapshot.add_transformer(snapshot.transform.key_value("ReceiptHandle"))
    snapshot.add_transformer(snapshot.transform.key_value("SenderId", reference_replacement=False))
    snapshot.add_transformer(snapshot.transform.resource_name())
    # body contains dynamic attributes so md5 hash changes
    snapshot.add_transformer(snapshot.transform.key_value("MD5OfBody"))
    # lower-case for when messages are rendered in lambdas
    snapshot.add_transformer(snapshot.transform.key_value("receiptHandle"))
    snapshot.add_transformer(snapshot.transform.key_value("md5OfBody"))


@pytest.mark.skip_snapshot_verify(
    paths=[
        # FIXME: this is most of the event source mapping unfortunately
        "$..ParallelizationFactor",
        "$..LastProcessingResult",
        "$..Topics",
        "$..MaximumRetryAttempts",
        "$..MaximumBatchingWindowInSeconds",
        "$..FunctionResponseTypes",
        "$..StartingPosition",
        "$..StateTransitionReason",
    ]
)
def test_failing_lambda_retries_after_visibility_timeout(
    create_lambda_function,
    lambda_client,
    sqs_client,
    sqs_create_queue,
    sqs_queue_arn,
    lambda_su_role,
    snapshot,
    cleanups,
):
    """This test verifies a basic SQS retry scenario. The lambda uses an SQS queue as event source, and we are
    testing whether the lambda automatically retries after the visibility timeout expires, and, after the retry,
    properly deletes the message from the queue."""

    # create queue used in the lambda to send events to (to verify lambda was invoked)
    destination_queue_name = f"destination-queue-{short_uid()}"
    destination_url = sqs_create_queue(QueueName=destination_queue_name)
    snapshot.match(
        "get_destination_queue_url", sqs_client.get_queue_url(QueueName=destination_queue_name)
    )

    retry_timeout = (
        2  # timeout in seconds, used for both the lambda and the queue visibility timeout
    )

    # set up lambda function
    function_name = f"failing-lambda-{short_uid()}"
    create_lambda_function(
        func_name=function_name,
        handler_file=LAMBDA_SQS_INTEGRATION_FILE,
        runtime=LAMBDA_RUNTIME_PYTHON38,
        role=lambda_su_role,
        timeout=retry_timeout,  # timeout needs to be <= than visibility timeout
    )

    # create event source queue
    event_source_url = sqs_create_queue(
        QueueName=f"source-queue-{short_uid()}",
        Attributes={
            # the visibility timeout is implicitly also the time between retries
            "VisibilityTimeout": str(retry_timeout),
        },
    )
    event_source_arn = sqs_queue_arn(event_source_url)

    # wire everything with the event source mapping
    response = lambda_client.create_event_source_mapping(
        EventSourceArn=event_source_arn,
        FunctionName=function_name,
        BatchSize=1,
    )
    mapping_uuid = response["UUID"]
    cleanups.append(lambda: lambda_client.delete_event_source_mapping(UUID=mapping_uuid))
    _await_event_source_mapping_enabled(lambda_client, mapping_uuid)
    response = lambda_client.get_event_source_mapping(UUID=mapping_uuid)
    snapshot.match("event_source_mapping", response)

    # trigger lambda with a message and pass the result destination url. the event format is expected by the
    # lambda_sqs_integration.py lambda.
    event = {"destination": destination_url, "fail_attempts": 1}
    sqs_client.send_message(
        QueueUrl=event_source_url,
        MessageBody=json.dumps(event),
    )

    # now wait for the first invocation result which is expected to fail
    then = time.time()
    first_response = sqs_client.receive_message(
        QueueUrl=destination_url, WaitTimeSeconds=15, MaxNumberOfMessages=1
    )
    assert "Messages" in first_response
    snapshot.match("first_attempt", first_response)

    # and then after a few seconds (at least the visibility timeout), we expect the
    second_response = sqs_client.receive_message(
        QueueUrl=destination_url, WaitTimeSeconds=15, MaxNumberOfMessages=1
    )
    assert "Messages" in second_response
    snapshot.match("second_attempt", second_response)

    # check that it took at least the retry timeout between the first and second attempt
    assert time.time() >= then + retry_timeout

    # assert message is removed from the queue
    assert "Messages" not in sqs_client.receive_message(
        QueueUrl=destination_url, WaitTimeSeconds=retry_timeout + 1, MaxNumberOfMessages=1
    )


@pytest.mark.skip_snapshot_verify(
    paths=[
        "$..ParallelizationFactor",
        "$..LastProcessingResult",
        "$..Topics",
        "$..MaximumRetryAttempts",
        "$..MaximumBatchingWindowInSeconds",
        "$..FunctionResponseTypes",
        "$..StartingPosition",
        "$..StateTransitionReason",
    ]
)
def test_redrive_policy_with_failing_lambda(
    create_lambda_function,
    lambda_client,
    sqs_client,
    sqs_create_queue,
    sqs_queue_arn,
    lambda_su_role,
    snapshot,
    cleanups,
):
    """This test verifies that SQS moves a message that is passed to a failing lambda to a DLQ according to the
    redrive policy, and the lambda is invoked the correct number of times. The test retries twice and the event
    source mapping should then automatically move the message to the DLQ, but not earlier (see
    https://github.com/localstack/localstack/issues/5283)"""

    # create queue used in the lambda to send events to (to verify lambda was invoked)
    destination_queue_name = f"destination-queue-{short_uid()}"
    destination_url = sqs_create_queue(QueueName=destination_queue_name)
    snapshot.match(
        "get_destination_queue_url", sqs_client.get_queue_url(QueueName=destination_queue_name)
    )

    retry_timeout = (
        2  # timeout in seconds, used for both the lambda and the queue visibility timeout
    )
    retries = 2

    # set up lambda function
    function_name = f"failing-lambda-{short_uid()}"
    create_lambda_function(
        func_name=function_name,
        handler_file=LAMBDA_SQS_INTEGRATION_FILE,
        runtime=LAMBDA_RUNTIME_PYTHON38,
        role=lambda_su_role,
        timeout=retry_timeout,  # timeout needs to be <= than visibility timeout
    )

    # create dlq for event source queue
    event_dlq_url = sqs_create_queue(QueueName=f"event-dlq-{short_uid()}")
    event_dlq_arn = sqs_queue_arn(event_dlq_url)

    # create event source queue
    event_source_url = sqs_create_queue(
        QueueName=f"source-queue-{short_uid()}",
        Attributes={
            # the visibility timeout is implicitly also the time between retries
            "VisibilityTimeout": str(retry_timeout),
            "RedrivePolicy": json.dumps(
                {"deadLetterTargetArn": event_dlq_arn, "maxReceiveCount": retries}
            ),
        },
    )
    event_source_arn = sqs_queue_arn(event_source_url)

    # wire everything with the event source mapping
    mapping_uuid = lambda_client.create_event_source_mapping(
        EventSourceArn=event_source_arn,
        FunctionName=function_name,
        BatchSize=1,
    )["UUID"]
    cleanups.append(lambda: lambda_client.delete_event_source_mapping(UUID=mapping_uuid))
    _await_event_source_mapping_enabled(lambda_client, mapping_uuid)

    # trigger lambda with a message and pass the result destination url. the event format is expected by the
    # lambda_sqs_integration.py lambda.
    event = {"destination": destination_url, "fail_attempts": retries}
    sqs_client.send_message(
        QueueUrl=event_source_url,
        MessageBody=json.dumps(event),
    )

    # now wait for the first invocation result which is expected to fail
    first_response = sqs_client.receive_message(
        QueueUrl=destination_url, WaitTimeSeconds=15, MaxNumberOfMessages=1
    )
    assert "Messages" in first_response
    snapshot.match("first_attempt", first_response)

    # check that the DLQ is empty
    assert "Messages" not in sqs_client.receive_message(QueueUrl=event_dlq_url, WaitTimeSeconds=1)

    # the second is also expected to fail, and then the message moves into the DLQ
    second_response = sqs_client.receive_message(
        QueueUrl=destination_url, WaitTimeSeconds=15, MaxNumberOfMessages=1
    )
    assert "Messages" in second_response
    snapshot.match("second_attempt", second_response)

    # now check that the event messages was placed in the DLQ
    dlq_response = sqs_client.receive_message(QueueUrl=event_dlq_url, WaitTimeSeconds=15)
    assert "Messages" in dlq_response
    snapshot.match("dlq_response", dlq_response)
