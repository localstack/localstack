from localstack.testing.pytest import markers
from localstack.utils.common import retry, short_uid

PUBLICATION_TIMEOUT = 1
PUBLICATION_RETRIES = 20


class TestNotifications:
    @markers.aws.validated
    def test_sqs_queue_names(self, aws_client):
        queue_name = f"{short_uid()}.fifo"

        # make sure we can create *.fifo queues
        try:
            queue = aws_client.sqs.create_queue(
                QueueName=queue_name, Attributes={"FifoQueue": "true"}
            )
            assert queue_name in queue["QueueUrl"]
        finally:
            aws_client.sqs.delete_queue(QueueUrl=queue["QueueUrl"])

    @markers.aws.validated
    def test_sns_to_sqs(
        self,
        sqs_create_queue,
        sns_create_topic,
        sns_allow_topic_sqs_queue,
        sqs_receive_num_messages,
        aws_client,
    ):
        # create topic and queue
        queue_url = sqs_create_queue()
        topic_info = sns_create_topic()
        topic_arn = topic_info["TopicArn"]
        # subscribe SQS to SNS, publish message
        queue_arn = aws_client.sqs.get_queue_attributes(
            QueueUrl=queue_url, AttributeNames=["QueueArn"]
        )["Attributes"]["QueueArn"]
        subscription = aws_client.sns.subscribe(
            TopicArn=topic_arn,
            Protocol="sqs",
            Endpoint=queue_arn,
        )
        sns_allow_topic_sqs_queue(
            sqs_queue_url=queue_url, sqs_queue_arn=queue_arn, sns_topic_arn=topic_arn
        )
        test_value = short_uid()
        aws_client.sns.publish(
            TopicArn=topic_arn,
            Message="test message for SQS",
            MessageAttributes={"attr1": {"DataType": "String", "StringValue": test_value}},
        )

        def assert_message():
            # receive, and delete message from SQS
            expected = {"attr1": {"Type": "String", "Value": test_value}}
            messages = sqs_receive_num_messages(queue_url, expected_messages=1)
            assert messages[0]["TopicArn"] == topic_arn
            assert expected == messages[0]["MessageAttributes"]

        retry(assert_message, retries=PUBLICATION_RETRIES, sleep=PUBLICATION_TIMEOUT)

        # cleanup
        aws_client.sns.unsubscribe(SubscriptionArn=subscription["SubscriptionArn"])
