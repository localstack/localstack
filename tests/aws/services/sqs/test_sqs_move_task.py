import json
import time
import uuid

import pytest
from botocore.exceptions import ClientError

from localstack.services.sqs.utils import decode_move_task_handle, encode_move_task_handle
from localstack.testing.pytest import markers
from localstack.utils.aws import arns
from localstack.utils.sync import retry

from .utils import sqs_wait_queue_size

QueueUrl = str


@pytest.fixture(autouse=True)
def sqs_snapshot_transformer(snapshot):
    snapshot.add_transformer(snapshot.transform.sqs_api())


@pytest.fixture()
def sqs_create_dlq_pipe(sqs_create_queue, region_name):
    def _factory(max_receive_count: int = 1) -> tuple[QueueUrl, QueueUrl]:
        dl_queue_url = sqs_create_queue()

        # create redrive policy
        url_parts = dl_queue_url.split("/")
        dl_target_arn = arns.sqs_queue_arn(
            url_parts[-1],
            account_id=url_parts[len(url_parts) - 2],
            region_name=region_name,
        )
        queue_url = sqs_create_queue(
            Attributes={
                "RedrivePolicy": json.dumps(
                    {
                        "deadLetterTargetArn": dl_target_arn,
                        "maxReceiveCount": max_receive_count,
                    }
                )
            },
        )
        return queue_url, dl_queue_url

    return _factory


@markers.aws.validated
def test_cancel_with_invalid_task_handle(aws_client, snapshot):
    with pytest.raises(ClientError) as e:
        aws_client.sqs.cancel_message_move_task(TaskHandle="foobared")
    snapshot.match("error", e.value.response)


@markers.aws.validated
def test_cancel_with_invalid_source_arn_in_task_handle(aws_client, snapshot):
    source_arn = "arn:aws:sqs:us-east-1:878966065785:test-queue-doesnt-exist-123456"
    task_handle = encode_move_task_handle("10f57157-fc38-4da9-a113-4de7e12d05dd", source_arn)

    with pytest.raises(ClientError) as e:
        aws_client.sqs.cancel_message_move_task(TaskHandle=task_handle)
    snapshot.match("error", e.value.response)


@markers.aws.validated
def test_cancel_with_invalid_task_id_in_task_handle(
    sqs_create_queue, sqs_get_queue_arn, aws_client, snapshot
):
    source_queue = sqs_create_queue()
    source_arn = sqs_get_queue_arn(source_queue)

    # this is just some non-existing task_id
    task_handle = encode_move_task_handle("10f57157-fc38-4da9-a113-4de7e12d05aa", source_arn)
    with pytest.raises(ClientError) as e:
        aws_client.sqs.cancel_message_move_task(TaskHandle=task_handle)
    snapshot.match("error", e.value.response)


@markers.aws.validated
def test_source_needs_redrive_policy(
    sqs_create_queue,
    sqs_get_queue_arn,
    aws_client,
    snapshot,
):
    sqs = aws_client.sqs

    source_queue = sqs_create_queue()
    source_arn = sqs_get_queue_arn(source_queue)

    destination_queue = sqs_create_queue()
    destination_arn = sqs_get_queue_arn(destination_queue)

    with pytest.raises(ClientError) as e:
        sqs.start_message_move_task(SourceArn=source_arn, DestinationArn=destination_arn)

    snapshot.match("error", e.value.response)


@markers.aws.validated
def test_destination_needs_to_exist(
    sqs_create_queue,
    sqs_create_dlq_pipe,
    sqs_get_queue_arn,
    aws_client,
    snapshot,
):
    sqs = aws_client.sqs
    queue_url, dl_queue_url = sqs_create_dlq_pipe(max_receive_count=1)
    source_arn = sqs_get_queue_arn(dl_queue_url)
    destination_queue = sqs_create_queue()
    destination_arn = sqs_get_queue_arn(destination_queue)
    destination_arn += "doesntexist"

    with pytest.raises(ClientError) as e:
        sqs.start_message_move_task(SourceArn=source_arn, DestinationArn=destination_arn)

    snapshot.match("error", e.value.response)


@markers.aws.validated
def test_basic_move_task_workflow(
    sqs_create_queue,
    sqs_create_dlq_pipe,
    sqs_get_queue_arn,
    sqs_collect_messages,
    aws_client,
    snapshot,
):
    sqs = aws_client.sqs

    # create dlq pipe: some-queue -> dlq (source) -> destination
    queue_url, dl_queue_url = sqs_create_dlq_pipe(max_receive_count=1)
    source_arn = sqs_get_queue_arn(dl_queue_url)
    destination_queue = sqs_create_queue()
    destination_arn = sqs_get_queue_arn(destination_queue)

    # send two messages
    sqs.send_message(QueueUrl=queue_url, MessageBody="message-1")
    sqs.send_message(QueueUrl=queue_url, MessageBody="message-2")

    # receive each message two times to move them into the dlq
    sqs.receive_message(QueueUrl=queue_url, VisibilityTimeout=0)
    sqs.receive_message(QueueUrl=queue_url, VisibilityTimeout=0)
    sqs.receive_message(QueueUrl=queue_url, VisibilityTimeout=0)
    sqs.receive_message(QueueUrl=queue_url, VisibilityTimeout=0)

    # wait until the messages arrive in the DLQ
    assert sqs_wait_queue_size(sqs, dl_queue_url, expected_num_messages=2, timeout=10) == 2

    response = aws_client.sqs.start_message_move_task(
        SourceArn=source_arn, DestinationArn=destination_arn
    )
    snapshot.match("start-message-move-task-response", response)

    # check task handle format
    task_handle = response["TaskHandle"]
    decoded_task_id, decoded_source_arn = decode_move_task_handle(task_handle)
    assert uuid.UUID(decoded_task_id)
    assert decoded_source_arn == source_arn

    # check that messages arrived in destination queue correctly
    messages = sqs_collect_messages(destination_queue, expected=2, timeout=10)
    assert {message["Body"] for message in messages} == {"message-1", "message-2"}

    # check move task completion (in AWS, approximate number of messages may take a while to update)
    def _wait_for_task_completion():
        _response = aws_client.sqs.list_message_move_tasks(SourceArn=source_arn)
        # this test also covers a check that `ApproximateNumberOfMessagesMoved` is set correctly at some point
        assert int(_response["Results"][0]["ApproximateNumberOfMessagesMoved"]) == 2
        return _response

    response = retry(_wait_for_task_completion, retries=30, sleep=1)
    snapshot.match("list-message-move-task-response", response)

    # assert messages are no longer in DLQ
    response = aws_client.sqs.receive_message(QueueUrl=dl_queue_url, WaitTimeSeconds=1)
    assert not response.get("Messages")


@markers.aws.validated
def test_move_task_workflow_with_default_destination(
    sqs_create_queue,
    sqs_create_dlq_pipe,
    sqs_get_queue_arn,
    sqs_collect_messages,
    aws_client,
    snapshot,
):
    # tests that, if the destination arn is left blank, the messages will be redriven back to their
    # respective original source queues.
    sqs = aws_client.sqs

    # create dlq pipe: some-queue -> dlq (source) -> some-queue
    queue_url, dl_queue_url = sqs_create_dlq_pipe(max_receive_count=1)
    source_arn = sqs_get_queue_arn(dl_queue_url)

    snapshot.match("source-arn", source_arn)
    snapshot.match("original-source", sqs_get_queue_arn(queue_url))

    # send two messages
    sqs.send_message(QueueUrl=queue_url, MessageBody="message-1")
    sqs.send_message(QueueUrl=queue_url, MessageBody="message-2")

    # receive each message two times to move them into the dlq
    sqs.receive_message(QueueUrl=queue_url, VisibilityTimeout=0)
    sqs.receive_message(QueueUrl=queue_url, VisibilityTimeout=0)
    sqs.receive_message(QueueUrl=queue_url, VisibilityTimeout=0)
    sqs.receive_message(QueueUrl=queue_url, VisibilityTimeout=0)

    # wait until the messages arrive in the DLQ
    assert sqs_wait_queue_size(sqs, dl_queue_url, expected_num_messages=2, timeout=10) == 2

    response = aws_client.sqs.start_message_move_task(SourceArn=source_arn)
    snapshot.match("start-message-move-task-response", response)

    # check task handle format
    task_handle = response["TaskHandle"]
    decoded_task_id, decoded_source_arn = decode_move_task_handle(task_handle)
    assert uuid.UUID(decoded_task_id)
    assert decoded_source_arn == source_arn

    # check that messages arrived in destination queue correctly
    messages = sqs_collect_messages(queue_url, expected=2, timeout=10)
    assert {message["Body"] for message in messages} == {"message-1", "message-2"}

    # check move task completion (in AWS, approximate number of messages may take a while to update)
    def _wait_for_task_completion():
        _response = aws_client.sqs.list_message_move_tasks(SourceArn=source_arn)
        # this test also covers a check that `ApproximateNumberOfMessagesMoved` is set correctly at some point
        assert int(_response["Results"][0]["ApproximateNumberOfMessagesMoved"]) == 2
        return _response

    response = retry(_wait_for_task_completion, retries=30, sleep=1)
    snapshot.match("list-message-move-task-response", response)

    # assert messages are no longer in DLQ
    response = aws_client.sqs.receive_message(QueueUrl=dl_queue_url, WaitTimeSeconds=1)
    assert not response.get("Messages")


@markers.aws.validated
def test_move_task_workflow_with_multiple_sources_as_default_destination(
    sqs_create_queue,
    sqs_create_dlq_pipe,
    sqs_get_queue_arn,
    sqs_collect_messages,
    aws_client,
    snapshot,
):
    # tests that, if the destination arn is left blank, the messages will be redriven back to their
    # respective original source queues, where there is more than one source queue.
    sqs = aws_client.sqs

    # create dlq pipe: some-queue -> dlq (source) -> some-queue
    queue1_url, dl_queue_url = sqs_create_dlq_pipe(max_receive_count=1)
    source_arn = sqs_get_queue_arn(dl_queue_url)
    # create another DLQ pipe with the same DLQ (re
    queue2_url = sqs_create_queue(
        Attributes={
            "RedrivePolicy": json.dumps(
                {
                    "deadLetterTargetArn": source_arn,
                    "maxReceiveCount": 1,
                }
            )
        },
    )

    snapshot.match("source-arn", source_arn)
    snapshot.match("original-source-1", sqs_get_queue_arn(queue1_url))
    snapshot.match("original-source-2", sqs_get_queue_arn(queue2_url))

    # send two messages to q1
    sqs.send_message(QueueUrl=queue1_url, MessageBody="message-1-1")
    sqs.send_message(QueueUrl=queue1_url, MessageBody="message-1-2")

    # send two messages to q2
    sqs.send_message(QueueUrl=queue2_url, MessageBody="message-2-1")
    sqs.send_message(QueueUrl=queue2_url, MessageBody="message-2-2")

    # receive each message two times to move them into the dlq
    sqs.receive_message(QueueUrl=queue1_url, VisibilityTimeout=0)
    sqs.receive_message(QueueUrl=queue1_url, VisibilityTimeout=0)
    sqs.receive_message(QueueUrl=queue1_url, VisibilityTimeout=0)
    sqs.receive_message(QueueUrl=queue1_url, VisibilityTimeout=0)
    sqs.receive_message(QueueUrl=queue2_url, VisibilityTimeout=0)
    sqs.receive_message(QueueUrl=queue2_url, VisibilityTimeout=0)
    sqs.receive_message(QueueUrl=queue2_url, VisibilityTimeout=0)
    sqs.receive_message(QueueUrl=queue2_url, VisibilityTimeout=0)

    # wait until the messages arrive in the DLQ
    assert sqs_wait_queue_size(sqs, dl_queue_url, expected_num_messages=4, timeout=10) == 4

    response = aws_client.sqs.start_message_move_task(SourceArn=source_arn)
    snapshot.match("start-message-move-task-response", response)

    # check that messages arrived in destination queue correctly
    messages = sqs_collect_messages(queue1_url, expected=2, timeout=10)
    assert {message["Body"] for message in messages} == {"message-1-1", "message-1-2"}

    messages = sqs_collect_messages(queue2_url, expected=2, timeout=10)
    assert {message["Body"] for message in messages} == {"message-2-1", "message-2-2"}

    # check move task completion (in AWS, approximate number of messages may take a while to update)
    def _wait_for_task_completion():
        _response = aws_client.sqs.list_message_move_tasks(SourceArn=source_arn)
        # this test also covers a check that `ApproximateNumberOfMessagesMoved` is set correctly at some point
        assert int(_response["Results"][0]["ApproximateNumberOfMessagesMoved"]) == 4
        return _response

    response = retry(_wait_for_task_completion, retries=30, sleep=1)
    snapshot.match("list-message-move-task-response", response)

    # assert messages are no longer in DLQ
    response = aws_client.sqs.receive_message(QueueUrl=dl_queue_url, WaitTimeSeconds=1)
    assert not response.get("Messages")


@markers.aws.validated
def test_move_task_with_throughput_limit(
    sqs_create_queue,
    sqs_create_dlq_pipe,
    sqs_get_queue_arn,
    sqs_collect_messages,
    aws_client,
    snapshot,
):
    sqs = aws_client.sqs

    # create dlq pipe: some-queue -> dlq (source) -> destination
    queue_url, dl_queue_url = sqs_create_dlq_pipe(max_receive_count=1)
    source_arn = sqs_get_queue_arn(dl_queue_url)
    destination_queue = sqs_create_queue()
    destination_arn = sqs_get_queue_arn(destination_queue)

    n = 4

    # send n messages and move them into the DLQ
    for i in range(n):
        sqs.send_message(QueueUrl=queue_url, MessageBody=f"message-{i}")

    assert sqs_wait_queue_size(sqs, queue_url, expected_num_messages=n, timeout=10) == n

    # receive each message two times to move them into the dlq
    for i in range(n * 2):
        sqs.receive_message(QueueUrl=queue_url, VisibilityTimeout=0)

    # wait until the messages arrive in the DLQ
    assert sqs_wait_queue_size(sqs, dl_queue_url, expected_num_messages=n, timeout=10) == n

    # start move task
    response = aws_client.sqs.start_message_move_task(
        SourceArn=source_arn, DestinationArn=destination_arn, MaxNumberOfMessagesPerSecond=1
    )
    snapshot.match("start-message-move-task-response", response)
    started = time.time()
    messages = sqs_collect_messages(destination_queue, n, 60)
    assert {message["Body"] for message in messages} == {
        "message-0",
        "message-1",
        "message-2",
        "message-3",
    }

    # we set the MaxNumberOfMessagesPerSecond to 1, so moving 4 messages should take at least 3 seconds (assuming
    # that the first one is moved immediately, and the task terminates immediately after the last message has been
    # moved)
    assert time.time() - started >= 3


@markers.aws.validated
@pytest.mark.skip_snapshot_verify(
    paths=[
        # this is non-deterministic because of concurrency in AWS vs LocalStack
        "$..ApproximateNumberOfMessagesMoved",
    ]
)
def test_move_task_cancel(
    sqs_create_queue,
    sqs_create_dlq_pipe,
    sqs_get_queue_arn,
    sqs_collect_messages,
    aws_client,
    snapshot,
):
    sqs = aws_client.sqs

    # create dlq pipe: some-queue -> dlq (source) -> destination
    queue_url, dl_queue_url = sqs_create_dlq_pipe(max_receive_count=1)
    source_arn = sqs_get_queue_arn(dl_queue_url)
    destination_queue = sqs_create_queue()
    destination_arn = sqs_get_queue_arn(destination_queue)

    n = 10

    # send n messages
    for i in range(n):
        sqs.send_message(QueueUrl=queue_url, MessageBody=f"message-{i}")

    assert sqs_wait_queue_size(sqs, queue_url, expected_num_messages=n, timeout=10) == n

    # receive each message two times to move them into the dlq
    for i in range(n * 2):
        sqs.receive_message(QueueUrl=queue_url, VisibilityTimeout=0)

    # wait until the messages arrive in the DLQ
    assert sqs_wait_queue_size(sqs, dl_queue_url, expected_num_messages=n, timeout=10) == n

    # start move task
    response = aws_client.sqs.start_message_move_task(
        SourceArn=source_arn, DestinationArn=destination_arn, MaxNumberOfMessagesPerSecond=1
    )
    task_handle = response["TaskHandle"]

    # wait for two messages to arrive, then cancel the task
    messages = sqs_collect_messages(destination_queue, 2, 60)
    assert len(messages) == 2

    response = sqs.list_message_move_tasks(SourceArn=source_arn)
    snapshot.match("list-while", response)

    response = sqs.cancel_message_move_task(TaskHandle=task_handle)
    snapshot.match("cancel", response)

    # check move task completion (in AWS, approximate number of messages may take a while to update)
    def _wait_for_task_cancellation():
        _response = aws_client.sqs.list_message_move_tasks(SourceArn=source_arn)
        assert _response["Results"][0]["Status"] == "CANCELLED"
        return _response

    response = retry(_wait_for_task_cancellation, retries=30, sleep=1)
    snapshot.match("list-after", response)

    # make sure that there are still messages left in the DLQ
    assert aws_client.sqs.receive_message(QueueUrl=dl_queue_url)["Messages"]


@markers.aws.validated
@pytest.mark.skip_snapshot_verify(
    paths=[
        # this is non-deterministic because of concurrency in AWS vs LocalStack
        "$..Results..ApproximateNumberOfMessagesMoved",
        # error serialization is still an issue ('AWS.SimpleQueueService.NonExistentQueue' vs
        # 'QueueDoesNotExist')
        "$..Results..FailureReason",
    ]
)
def test_move_task_delete_destination_queue_while_running(
    sqs_create_queue,
    sqs_create_dlq_pipe,
    sqs_get_queue_arn,
    aws_client,
    snapshot,
):
    sqs = aws_client.sqs

    # create dlq pipe: some-queue -> dlq (source) -> destination
    queue_url, dl_queue_url = sqs_create_dlq_pipe(max_receive_count=1)
    source_arn = sqs_get_queue_arn(dl_queue_url)
    destination_queue = sqs_create_queue()
    destination_arn = sqs_get_queue_arn(destination_queue)

    n = 10

    # send n messages
    for i in range(n):
        sqs.send_message(QueueUrl=queue_url, MessageBody=f"message-{i}")

    assert sqs_wait_queue_size(sqs, queue_url, expected_num_messages=n, timeout=10) == n

    # receive each message two times to move them into the dlq
    for i in range(n * 2):
        sqs.receive_message(QueueUrl=queue_url, VisibilityTimeout=0)

    # wait until the messages arrive in the DLQ
    assert sqs_wait_queue_size(sqs, dl_queue_url, expected_num_messages=n, timeout=10) == n

    # start move task
    aws_client.sqs.start_message_move_task(
        SourceArn=source_arn, DestinationArn=destination_arn, MaxNumberOfMessagesPerSecond=1
    )

    sqs.delete_queue(QueueUrl=destination_queue)

    # check move task completion (in AWS, approximate number of messages may take a while to update)
    def _wait_for_task_cancellation():
        _response = aws_client.sqs.list_message_move_tasks(SourceArn=source_arn)
        assert _response["Results"][0]["Status"] != "RUNNING"
        return _response

    # should fail
    response = retry(_wait_for_task_cancellation, retries=30, sleep=1)
    print(response)
    snapshot.match("list", response)

    # make sure that there are still messages left in the DLQ
    assert aws_client.sqs.receive_message(QueueUrl=dl_queue_url)["Messages"]


@markers.aws.validated
def test_start_multiple_move_tasks(
    sqs_create_queue,
    sqs_create_dlq_pipe,
    sqs_get_queue_arn,
    aws_client,
    snapshot,
):
    sqs = aws_client.sqs

    # create dlq pipe: some-queue -> dlq (source) -> destination
    queue_url, dl_queue_url = sqs_create_dlq_pipe(max_receive_count=1)
    source_arn = sqs_get_queue_arn(dl_queue_url)
    destination_queue = sqs_create_queue()
    destination_arn = sqs_get_queue_arn(destination_queue)

    n = 10

    # send n messages
    for i in range(n):
        sqs.send_message(QueueUrl=queue_url, MessageBody=f"message-{i}")

    assert sqs_wait_queue_size(sqs, queue_url, expected_num_messages=n, timeout=10) == n

    # receive each message two times to move them into the dlq
    for i in range(n * 2):
        sqs.receive_message(QueueUrl=queue_url, VisibilityTimeout=0)

    # wait until the messages arrive in the DLQ
    assert sqs_wait_queue_size(sqs, dl_queue_url, expected_num_messages=n, timeout=10) == n

    # start move task
    aws_client.sqs.start_message_move_task(
        SourceArn=source_arn, DestinationArn=destination_arn, MaxNumberOfMessagesPerSecond=1
    )
    with pytest.raises(ClientError) as e:
        aws_client.sqs.start_message_move_task(
            SourceArn=source_arn, DestinationArn=destination_arn, MaxNumberOfMessagesPerSecond=1
        )
    snapshot.match("error", e.value.response)
