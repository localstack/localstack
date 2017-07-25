import json
from io import BytesIO
from localstack.config import HOSTNAME, PORT_SQS
from localstack.constants import TEST_AWS_ACCOUNT_ID
from localstack.utils import testutil
from localstack.utils.aws import aws_stack
from localstack.utils.common import to_str, short_uid

TEST_BUCKET_NAME_WITH_NOTIFICATIONS = 'test_bucket_2'
TEST_QUEUE_NAME_FOR_S3 = 'test_queue'
TEST_TOPIC_NAME = 'test_topic_name_for_sqs'
TEST_QUEUE_NAME_FOR_SNS = 'test_queue_for_sns'


def receive_assert_delete(queue_url, assertions, sqs_client=None):
    if not sqs_client:
        sqs_client = aws_stack.connect_to_service('sqs')

    response = sqs_client.receive_message(QueueUrl=queue_url)
    messages = [json.loads(to_str(m['Body'])) for m in response['Messages']]
    testutil.assert_objects(assertions, messages)
    for message in response['Messages']:
        sqs_client.delete_message(QueueUrl=queue_url, ReceiptHandle=message['ReceiptHandle'])


def test_sns_to_sqs():
    sqs_client = aws_stack.connect_to_service('sqs')
    sns_client = aws_stack.connect_to_service('sns')

    # create topic and queue
    queue_info = sqs_client.create_queue(QueueName=TEST_QUEUE_NAME_FOR_SNS)
    topic_info = sns_client.create_topic(Name=TEST_TOPIC_NAME)

    # subscribe SQS to SNS, publish message
    sns_client.subscribe(TopicArn=topic_info['TopicArn'], Protocol='sqs',
        Endpoint=aws_stack.sqs_queue_arn(TEST_QUEUE_NAME_FOR_SNS))
    test_value = short_uid()
    sns_client.publish(TopicArn=topic_info['TopicArn'], Message='test message for SQS',
        MessageAttributes={'attr1': {'DataType': 'String', 'StringValue': test_value}})

    # receive, assert, and delete message from SQS
    queue_url = queue_info['QueueUrl']
    assertions = []
    # make sure we receive the correct topic ARN in notifications
    assertions.append({'TopicArn': topic_info['TopicArn']})
    # make sure the notification contains message attributes
    assertions.append({'Value': test_value})
    receive_assert_delete(queue_url, assertions, sqs_client)


def test_bucket_notifications():

    s3_resource = aws_stack.connect_to_resource('s3')
    s3_client = aws_stack.connect_to_service('s3')
    sqs_client = aws_stack.connect_to_service('sqs')

    # create test bucket and queue
    s3_resource.create_bucket(Bucket=TEST_BUCKET_NAME_WITH_NOTIFICATIONS)
    queue_info = sqs_client.create_queue(QueueName=TEST_QUEUE_NAME_FOR_S3)

    # create notification on bucket
    queue_url = queue_info['QueueUrl']
    queue_arn = aws_stack.sqs_queue_arn(TEST_QUEUE_NAME_FOR_S3)
    s3_client.put_bucket_notification_configuration(
        Bucket=TEST_BUCKET_NAME_WITH_NOTIFICATIONS,
        NotificationConfiguration={
            'QueueConfigurations': [
                {
                    'Id': 'id123456',
                    'QueueArn': queue_arn,
                    'Events': ['s3:ObjectCreated:*', 's3:ObjectRemoved:Delete']
                }
            ]
        }
    )

    # upload file to S3
    test_prefix = '/testdata'
    test_data = b'{"test": "bucket_notification"}'
    s3_client.upload_fileobj(BytesIO(test_data), TEST_BUCKET_NAME_WITH_NOTIFICATIONS, test_prefix)

    # receive, assert, and delete message from SQS
    receive_assert_delete(queue_url, {'name': TEST_BUCKET_NAME_WITH_NOTIFICATIONS}, sqs_client)
