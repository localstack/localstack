import json
from io import BytesIO
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


def test_sqs_queue_names():
    sqs_client = aws_stack.connect_to_service('sqs')
    queue_name = '%s.fifo' % short_uid()
    # make sure we can create *.fifo queues
    queue_url = sqs_client.create_queue(QueueName=queue_name)['QueueUrl']
    sqs_client.delete_queue(QueueUrl=queue_url)


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
    events = ['s3:ObjectCreated:*', 's3:ObjectRemoved:Delete']
    s3_client.put_bucket_notification_configuration(
        Bucket=TEST_BUCKET_NAME_WITH_NOTIFICATIONS,
        NotificationConfiguration={
            'QueueConfigurations': [{
                'Id': 'id123456',
                'QueueArn': queue_arn,
                'Events': events,
                'Filter': {
                    'Key': {
                        'FilterRules': [{
                            'Name': 'prefix',
                            'Value': 'testupload/'
                        }, {
                            'Name': 'suffix',
                            'Value': 'testfile.txt'
                        }]
                    }
                }
            }]
        }
    )

    # retrieve and check notification config
    config = s3_client.get_bucket_notification_configuration(Bucket=TEST_BUCKET_NAME_WITH_NOTIFICATIONS)
    config = config['QueueConfigurations'][0]
    assert events == config['Events']

    # upload file to S3 (this should NOT trigger a notification)
    test_key1 = '/testdata'
    test_data1 = b'{"test": "bucket_notification1"}'
    s3_client.upload_fileobj(BytesIO(test_data1), TEST_BUCKET_NAME_WITH_NOTIFICATIONS, test_key1)

    # upload file to S3 (this should trigger a notification)
    test_key2 = 'testupload/dir1/testfile.txt'
    test_data2 = b'{"test": "bucket_notification2"}'
    s3_client.upload_fileobj(BytesIO(test_data2), TEST_BUCKET_NAME_WITH_NOTIFICATIONS, test_key2)

    # receive, assert, and delete message from SQS
    receive_assert_delete(queue_url, [{'key': test_key2}, {'name': TEST_BUCKET_NAME_WITH_NOTIFICATIONS}], sqs_client)
