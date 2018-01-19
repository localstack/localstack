import os
import json
import requests
from localstack.utils.aws import aws_stack

TEST_BUCKET_NAME_WITH_POLICY = 'test_bucket_policy_1'
TEST_BUCKET_WITH_NOTIFICATION = 'test_bucket_notification_1'
TEST_QUEUE_FOR_BUCKET_WITH_NOTIFICATION = 'test_queue_for_bucket_notification_1'


def test_bucket_policy():

    s3_resource = aws_stack.connect_to_resource('s3')
    s3_client = aws_stack.connect_to_service('s3')

    # create test bucket
    s3_resource.create_bucket(Bucket=TEST_BUCKET_NAME_WITH_POLICY)

    # put bucket policy
    policy = {
        'Version': '2012-10-17',
        'Statement': {
            'Action': ['s3:GetObject'],
            'Effect': 'Allow',
            'Resource': 'arn:aws:s3:::bucketName/*',
            'Principal': {
                'AWS': ['*']
            }
        }
    }
    response = s3_client.put_bucket_policy(
        Bucket=TEST_BUCKET_NAME_WITH_POLICY,
        Policy=json.dumps(policy)
    )
    assert response['ResponseMetadata']['HTTPStatusCode'] == 204

    # retrieve and check policy config
    saved_policy = s3_client.get_bucket_policy(Bucket=TEST_BUCKET_NAME_WITH_POLICY)['Policy']
    assert json.loads(saved_policy) == policy


def test_s3_put_object_notification():

    s3_client = aws_stack.connect_to_service('s3')
    sqs_client = aws_stack.connect_to_service('sqs')

    key_by_path = 'key-by-hostname'
    key_by_host = 'key-by-host'

    # create test queue
    queue_url = sqs_client.create_queue(QueueName=TEST_QUEUE_FOR_BUCKET_WITH_NOTIFICATION)['QueueUrl']
    queue_attributes = sqs_client.get_queue_attributes(QueueUrl=queue_url, AttributeNames=['QueueArn'])

    # create test bucket
    s3_client.create_bucket(Bucket=TEST_BUCKET_WITH_NOTIFICATION)
    s3_client.put_bucket_notification_configuration(Bucket=TEST_BUCKET_WITH_NOTIFICATION,
                                                    NotificationConfiguration={'QueueConfigurations': [
                                                        {'QueueArn': queue_attributes['Attributes']['QueueArn'],
                                                         'Events': ['s3:ObjectCreated:*']}]})

    # put an object where the bucket_name is in the path
    s3_client.put_object(Bucket=TEST_BUCKET_WITH_NOTIFICATION, Key=key_by_path, Body='something')

    # put an object where the bucket_name is in the host
    # it doesn't care about the authorization header as long as it's present
    headers = {'Host': '{}.s3.amazonaws.com'.format(TEST_BUCKET_WITH_NOTIFICATION), 'authorization': 'some_token'}
    url = '{}/{}'.format(os.getenv('TEST_S3_URL'), key_by_host)
    # verify=False must be set as this test fails on travis because of an SSL error non-existent locally
    response = requests.put(url, data='something else', headers=headers, verify=False)
    assert response.ok

    queue_attributes = sqs_client.get_queue_attributes(QueueUrl=queue_url,
                                                       AttributeNames=['ApproximateNumberOfMessages'])
    message_count = queue_attributes['Attributes']['ApproximateNumberOfMessages']
    # the ApproximateNumberOfMessages attribute is a string
    assert message_count == '2'

    # clean up
    sqs_client.delete_queue(QueueUrl=queue_url)
    s3_client.delete_objects(Bucket=TEST_BUCKET_WITH_NOTIFICATION,
                             Delete={'Objects': [{'Key': key_by_path}, {'Key': key_by_host}]})
    s3_client.delete_bucket(Bucket=TEST_BUCKET_WITH_NOTIFICATION)
