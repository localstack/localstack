import json
import unittest
from io import BytesIO
from localstack.utils import testutil
from localstack.utils.aws import aws_stack
from localstack.utils.common import to_str, short_uid

TEST_BUCKET_NAME_WITH_NOTIFICATIONS = 'test-bucket-notif-1'
TEST_QUEUE_NAME_FOR_S3 = 'test_queue'
TEST_TOPIC_NAME = 'test_topic_name_for_sqs'
TEST_S3_TOPIC_NAME = 'test_topic_name_for_s3_to_sns_to_sqs'
TEST_QUEUE_NAME_FOR_SNS = 'test_queue_for_sns'


class TestNotifications(unittest.TestCase):

    def test_sqs_queue_names(self):
        sqs_client = aws_stack.connect_to_service('sqs')
        queue_name = '%s.fifo' % short_uid()
        # make sure we can create *.fifo queues
        queue_url = sqs_client.create_queue(QueueName=queue_name, Attributes={'FifoQueue': 'true'})['QueueUrl']
        sqs_client.delete_queue(QueueUrl=queue_url)

    def test_sns_to_sqs(self):
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
        self._receive_assert_delete(queue_url, assertions, sqs_client)

    def test_bucket_notifications(self):

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
        filter_rules = {
            'FilterRules': [{
                'Name': 'prefix',
                'Value': 'testupload/'
            }, {
                'Name': 'suffix',
                'Value': 'testfile.txt'
            }]
        }
        s3_client.put_bucket_notification_configuration(
            Bucket=TEST_BUCKET_NAME_WITH_NOTIFICATIONS,
            NotificationConfiguration={
                'QueueConfigurations': [{
                    'Id': 'id0001',
                    'QueueArn': queue_arn,
                    'Events': events,
                    'Filter': {
                        'Key': filter_rules
                    }
                }, {
                    # Add second dummy config to fix https://github.com/localstack/localstack/issues/450
                    'Id': 'id0002',
                    'QueueArn': queue_arn,
                    'Events': [],
                    'Filter': {
                        'Key': filter_rules
                    }
                }]
            }
        )

        # retrieve and check notification config
        config = s3_client.get_bucket_notification_configuration(Bucket=TEST_BUCKET_NAME_WITH_NOTIFICATIONS)
        self.assertEqual(len(config['QueueConfigurations']), 2)
        config = [c for c in config['QueueConfigurations'] if c['Events']][0]
        self.assertEqual(events, config['Events'])
        self.assertEqual(filter_rules, config['Filter']['Key'])

        # upload file to S3 (this should NOT trigger a notification)
        test_key1 = '/testdata'
        test_data1 = b'{"test": "bucket_notification1"}'
        s3_client.upload_fileobj(BytesIO(test_data1), TEST_BUCKET_NAME_WITH_NOTIFICATIONS, test_key1)

        # upload file to S3 (this should trigger a notification)
        test_key2 = 'testupload/dir1/testfile.txt'
        test_data2 = b'{"test": "bucket_notification2"}'
        s3_client.upload_fileobj(BytesIO(test_data2), TEST_BUCKET_NAME_WITH_NOTIFICATIONS, test_key2)

        # receive, assert, and delete message from SQS
        self._receive_assert_delete(queue_url,
            [{'key': test_key2}, {'name': TEST_BUCKET_NAME_WITH_NOTIFICATIONS}], sqs_client)

        # delete notification config
        self._delete_notification_config()

        # put notification config with single event type
        event = 's3:ObjectCreated:*'
        s3_client.put_bucket_notification_configuration(Bucket=TEST_BUCKET_NAME_WITH_NOTIFICATIONS,
            NotificationConfiguration={
                'QueueConfigurations': [{
                    'Id': 'id123456',
                    'QueueArn': queue_arn,
                    'Events': [event]
                }]
            }
        )
        config = s3_client.get_bucket_notification_configuration(Bucket=TEST_BUCKET_NAME_WITH_NOTIFICATIONS)
        config = config['QueueConfigurations'][0]
        self.assertEqual(config['Events'], [event])

        # put notification config with single event type
        event = 's3:ObjectCreated:*'
        filter_rules = {
            'FilterRules': [{
                'Name': 'prefix',
                'Value': 'testupload/'
            }]
        }
        s3_client.put_bucket_notification_configuration(Bucket=TEST_BUCKET_NAME_WITH_NOTIFICATIONS,
            NotificationConfiguration={
                'QueueConfigurations': [{
                    'Id': 'id123456',
                    'QueueArn': queue_arn,
                    'Events': [event],
                    'Filter': {
                        'Key': filter_rules
                    }
                }]
            }
        )
        config = s3_client.get_bucket_notification_configuration(Bucket=TEST_BUCKET_NAME_WITH_NOTIFICATIONS)
        config = config['QueueConfigurations'][0]
        self.assertEqual(config['Events'], [event])
        self.assertEqual(filter_rules, config['Filter']['Key'])

        # upload file to S3 (this should trigger a notification)
        test_key2 = 'testupload/dir1/testfile.txt'
        test_data2 = b'{"test": "bucket_notification2"}'
        s3_client.upload_fileobj(BytesIO(test_data2), TEST_BUCKET_NAME_WITH_NOTIFICATIONS, test_key2)
        # receive, assert, and delete message from SQS
        self._receive_assert_delete(queue_url,
            [{'key': test_key2}, {'name': TEST_BUCKET_NAME_WITH_NOTIFICATIONS}], sqs_client)

        # delete notification config
        self._delete_notification_config()

        #
        # Tests s3->sns->sqs notifications
        #
        sns_client = aws_stack.connect_to_service('sns')
        topic_info = sns_client.create_topic(Name=TEST_S3_TOPIC_NAME)

        s3_client.put_bucket_notification_configuration(
            Bucket=TEST_BUCKET_NAME_WITH_NOTIFICATIONS,
            NotificationConfiguration={
                'TopicConfigurations': [
                    {
                        'Id': 'id123',
                        'Events': ['s3:ObjectCreated:*'],
                        'TopicArn': topic_info['TopicArn']
                    }
                ]
            })

        sns_client.subscribe(TopicArn=topic_info['TopicArn'], Protocol='sqs', Endpoint=queue_arn)

        test_key2 = 'testupload/dir1/testfile.txt'
        test_data2 = b'{"test": "bucket_notification2"}'

        s3_client.upload_fileobj(BytesIO(test_data2), TEST_BUCKET_NAME_WITH_NOTIFICATIONS, test_key2)

        # verify subject and records

        response = sqs_client.receive_message(QueueUrl=queue_url)
        for message in response['Messages']:
            snsObj = json.loads(message['Body'])
            testutil.assert_object({'Subject': 'Amazon S3 Notification'}, snsObj)
            notificationObj = json.loads(snsObj['Message'])
            testutil.assert_objects(
                [
                    {'key': test_key2},
                    {'name': TEST_BUCKET_NAME_WITH_NOTIFICATIONS}
                ], notificationObj['Records'])

            sqs_client.delete_message(QueueUrl=queue_url, ReceiptHandle=message['ReceiptHandle'])

        self._delete_notification_config()

    def _delete_notification_config(self):
        s3_client = aws_stack.connect_to_service('s3')
        s3_client.put_bucket_notification_configuration(
            Bucket=TEST_BUCKET_NAME_WITH_NOTIFICATIONS, NotificationConfiguration={})
        config = s3_client.get_bucket_notification_configuration(Bucket=TEST_BUCKET_NAME_WITH_NOTIFICATIONS)
        self.assertFalse(config.get('QueueConfigurations'))
        self.assertFalse(config.get('TopicConfiguration'))

    def _receive_assert_delete(self, queue_url, assertions, sqs_client=None, required_subject=None):
        if not sqs_client:
            sqs_client = aws_stack.connect_to_service('sqs')

        response = sqs_client.receive_message(QueueUrl=queue_url)

        messages = [json.loads(to_str(m['Body'])) for m in response['Messages']]
        testutil.assert_objects(assertions, messages)
        for message in response['Messages']:
            sqs_client.delete_message(QueueUrl=queue_url, ReceiptHandle=message['ReceiptHandle'])
