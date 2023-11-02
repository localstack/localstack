from datetime import datetime

from localstack.aws.connect import connect_externally_to
from localstack.constants import (
    TEST_AWS_ACCESS_KEY_ID,
    TEST_AWS_REGION_NAME,
    TEST_AWS_SECRET_ACCESS_KEY,
)
from localstack.utils.aws.arns import sqs_queue_url_for_arn

QUEUE_NAME = "test-perf-3610"
NUM_MESSAGES = 300


def print_duration(start, num_msgs, action):
    if num_msgs % 100 != 0:
        return
    duration = datetime.now() - start
    duration = duration.total_seconds()
    req_sec = num_msgs / duration
    print("%s %s messages in %s seconds (%s req/sec)" % (action, num_msgs, duration, req_sec))


def send_messages():
    sqs = connect_externally_to(
        region_name=TEST_AWS_REGION_NAME,
        aws_access_key_id=TEST_AWS_ACCESS_KEY_ID,
        aws_secret_access_key=TEST_AWS_SECRET_ACCESS_KEY,
    ).sqs
    queue_url = sqs.create_queue(QueueName=QUEUE_NAME)["QueueUrl"]

    print("Starting to send %s messages" % NUM_MESSAGES)
    start = datetime.now()
    for i in range(1, NUM_MESSAGES + 1):
        sqs.send_message(QueueUrl=queue_url, MessageBody="test123")
        print_duration(start, i, action="Sent")


def receive_messages():
    sqs = connect_externally_to(
        region_name=TEST_AWS_REGION_NAME,
        aws_access_key_id=TEST_AWS_ACCESS_KEY_ID,
        aws_secret_access_key=TEST_AWS_SECRET_ACCESS_KEY,
    ).sqs
    queue_url = sqs_queue_url_for_arn(QUEUE_NAME)
    messages = []

    start = datetime.now()
    while len(messages) < NUM_MESSAGES:
        result = sqs.receive_message(QueueUrl=queue_url)
        messages.extend(result.get("Messages") or [])
        print_duration(start, len(messages), action="Received")
    print("All %s messages received" % len(messages))


def main():
    send_messages()
    receive_messages()


if __name__ == "__main__":
    main()
