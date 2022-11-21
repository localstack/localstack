import pytest

from localstack.utils.common import retry, short_uid

PUBLICATION_TIMEOUT = 1
PUBLICATION_RETRIES = 20


class TestNotifications:
    @pytest.mark.aws_validated
    def test_sqs_queue_names(self, sqs_client):
        queue_name = f"{short_uid()}.fifo"

        # make sure we can create *.fifo queues
        try:
            queue = sqs_client.create_queue(QueueName=queue_name, Attributes={"FifoQueue": "true"})
            assert queue_name in queue["QueueUrl"]
        finally:
            sqs_client.delete_queue(QueueUrl=queue["QueueUrl"])

    def test_sns_to_sqs(
        self,
        sqs_client,
        sns_client,
        sqs_create_queue,
        sns_create_topic,
        sqs_receive_num_messages,
    ):

        # create topic and queue
        queue_url = sqs_create_queue()
        topic_info = sns_create_topic()
        topic_arn = topic_info["TopicArn"]
        # subscribe SQS to SNS, publish message
        queue_arn = sqs_client.get_queue_attributes(
            QueueUrl=queue_url, AttributeNames=["QueueArn"]
        )["Attributes"]["QueueArn"]
        subscription = sns_client.subscribe(
            TopicArn=topic_arn,
            Protocol="sqs",
            Endpoint=queue_arn,
        )
        test_value = short_uid()
        sns_client.publish(
            TopicArn=topic_arn,
            Message="test message for SQS",
            MessageAttributes={"attr1": {"DataType": "String", "StringValue": test_value}},
        )
        # cleanup
        sns_client.unsubscribe(SubscriptionArn=subscription["SubscriptionArn"])

        def assert_message():
            # receive, and delete message from SQS
            expected = {"attr1": {"Type": "String", "Value": test_value}}
            messages = sqs_receive_num_messages(queue_url, expected_messages=1)
            assert messages[0]["TopicArn"] == topic_arn
            assert expected == messages[0]["MessageAttributes"]

        retry(assert_message, retries=PUBLICATION_RETRIES, sleep=PUBLICATION_TIMEOUT)
