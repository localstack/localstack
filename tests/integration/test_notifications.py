import json
import unittest
from io import BytesIO

from botocore.exceptions import ClientError

from localstack.utils import testutil
from localstack.utils.aws import aws_stack
from localstack.utils.common import retry, short_uid, to_str

TEST_BUCKET_NAME_WITH_NOTIFICATIONS = "test-bucket-notif-1"
TEST_QUEUE_NAME_FOR_S3 = "test_queue"
TEST_TOPIC_NAME = "test_topic_name_for_sqs"
TEST_S3_TOPIC_NAME = "test_topic_name_for_s3_to_sns_to_sqs"
TEST_QUEUE_NAME_FOR_SNS = "test_queue_for_sns"
PUBLICATION_TIMEOUT = 0.500
PUBLICATION_RETRIES = 4


class TestNotifications(unittest.TestCase):
    def setUp(self):
        self.s3_client = aws_stack.create_external_boto_client("s3")
        self.sqs_client = aws_stack.create_external_boto_client("sqs")
        self.sns_client = aws_stack.create_external_boto_client("sns")

    def test_sqs_queue_names(self):
        sqs_client = self.sqs_client
        queue_name = "%s.fifo" % short_uid()
        # make sure we can create *.fifo queues
        queue_url = sqs_client.create_queue(QueueName=queue_name, Attributes={"FifoQueue": "true"})[
            "QueueUrl"
        ]
        sqs_client.delete_queue(QueueUrl=queue_url)

    def test_sns_to_sqs(self):
        sqs_client = self.sqs_client
        sns_client = self.sns_client

        # create topic and queue
        queue_info = sqs_client.create_queue(QueueName=TEST_QUEUE_NAME_FOR_SNS)
        topic_info = sns_client.create_topic(Name=TEST_TOPIC_NAME)

        # subscribe SQS to SNS, publish message
        subscription_arn = sns_client.subscribe(
            TopicArn=topic_info["TopicArn"],
            Protocol="sqs",
            Endpoint=aws_stack.sqs_queue_arn(TEST_QUEUE_NAME_FOR_SNS),
        )["SubscriptionArn"]
        test_value = short_uid()
        sns_client.publish(
            TopicArn=topic_info["TopicArn"],
            Message="test message for SQS",
            MessageAttributes={"attr1": {"DataType": "String", "StringValue": test_value}},
        )
        # cleanup
        sns_client.unsubscribe(SubscriptionArn=subscription_arn)

        def assert_message():
            # receive, assert, and delete message from SQS
            queue_url = queue_info["QueueUrl"]
            assertions = []
            # make sure we receive the correct topic ARN in notifications
            assertions.append({"TopicArn": topic_info["TopicArn"]})
            # make sure the notification contains message attributes
            assertions.append({"StringValue": test_value})
            self._receive_assert_delete(queue_url, assertions, sqs_client)

        retry(assert_message, retries=PUBLICATION_RETRIES, sleep=PUBLICATION_TIMEOUT)

    def test_put_bucket_notification_with_invalid_filter_rules(self):
        bucket_name = self.create_test_bucket()
        queue_url, queue_attributes = self.create_test_queue()

        cfg = {
            "QueueConfigurations": [
                {
                    "QueueArn": queue_attributes["Attributes"]["QueueArn"],
                    "Events": ["s3:ObjectCreated:*"],
                    "Filter": {
                        "Key": {"FilterRules": [{"Name": "INVALID", "Value": "does not matter"}]}
                    },
                }
            ]
        }

        try:
            with self.assertRaises(ClientError) as error:
                self.s3_client.put_bucket_notification_configuration(
                    Bucket=bucket_name, NotificationConfiguration=cfg
                )
            self.assertIn("InvalidArgument", str(error.exception))
        finally:
            self.sqs_client.delete_queue(QueueUrl=queue_url)
            self.s3_client.delete_bucket(Bucket=bucket_name)

    def test_put_and_get_bucket_notification_with_filter_rules(self):
        bucket_name = self.create_test_bucket()
        queue_url, queue_attributes = self.create_test_queue()

        cfg = {
            "QueueConfigurations": [
                {
                    "QueueArn": queue_attributes["Attributes"]["QueueArn"],
                    "Events": ["s3:ObjectCreated:*"],
                    "Filter": {
                        "Key": {
                            "FilterRules": [
                                {
                                    "Name": "suffix",
                                    "Value": ".txt",
                                },  # different casing should be normalized to Suffix/Prefix
                                {"Name": "PREFIX", "Value": "notif-"},
                            ]
                        }
                    },
                }
            ]
        }

        try:
            self.s3_client.put_bucket_notification_configuration(
                Bucket=bucket_name, NotificationConfiguration=cfg
            )
            response = self.s3_client.get_bucket_notification_configuration(Bucket=bucket_name)
            # verify casing of filter rule names
            rules = response["QueueConfigurations"].pop()["Filter"]["Key"]["FilterRules"]
            valid = ["Prefix", "Suffix"]

            self.assertIn(rules[0]["Name"], valid)
            self.assertIn(rules[1]["Name"], valid)

        finally:
            self.sqs_client.delete_queue(QueueUrl=queue_url)
            self.s3_client.delete_bucket(Bucket=bucket_name)

    def test_bucket_notifications(self):
        s3_resource = aws_stack.connect_to_resource("s3")
        s3_client = self.s3_client
        sqs_client = self.sqs_client

        # create test bucket and queue
        s3_resource.create_bucket(Bucket=TEST_BUCKET_NAME_WITH_NOTIFICATIONS)
        queue_info = sqs_client.create_queue(QueueName=TEST_QUEUE_NAME_FOR_S3)

        # create notification on bucket
        queue_url = queue_info["QueueUrl"]
        queue_arn = aws_stack.sqs_queue_arn(TEST_QUEUE_NAME_FOR_S3)
        events = ["s3:ObjectCreated:*", "s3:ObjectRemoved:Delete"]
        filter_rules = {
            "FilterRules": [
                {"Name": "Prefix", "Value": "testupload/"},
                {"Name": "Suffix", "Value": "testfile.txt"},
            ]
        }
        s3_client.put_bucket_notification_configuration(
            Bucket=TEST_BUCKET_NAME_WITH_NOTIFICATIONS,
            NotificationConfiguration={
                "QueueConfigurations": [
                    {
                        "Id": "id0001",
                        "QueueArn": queue_arn,
                        "Events": events,
                        "Filter": {"Key": filter_rules},
                    },
                    {
                        # Add second dummy config to fix https://github.com/localstack/localstack/issues/450
                        "Id": "id0002",
                        "QueueArn": queue_arn,
                        "Events": [],
                        "Filter": {"Key": filter_rules},
                    },
                ]
            },
        )

        # retrieve and check notification config
        config = s3_client.get_bucket_notification_configuration(
            Bucket=TEST_BUCKET_NAME_WITH_NOTIFICATIONS
        )
        self.assertEqual(2, len(config["QueueConfigurations"]))
        config = [c for c in config["QueueConfigurations"] if c["Events"]][0]
        self.assertEqual(events, config["Events"])
        self.assertEqual(filter_rules, config["Filter"]["Key"])

        # upload file to S3 (this should NOT trigger a notification)
        test_key1 = "/testdata"
        test_data1 = b'{"test": "bucket_notification1"}'
        s3_client.upload_fileobj(
            BytesIO(test_data1), TEST_BUCKET_NAME_WITH_NOTIFICATIONS, test_key1
        )

        # upload file to S3 (this should trigger a notification)
        test_key2 = "testupload/dir1/testfile.txt"
        test_data2 = b'{"test": "bucket_notification2"}'
        s3_client.upload_fileobj(
            BytesIO(test_data2), TEST_BUCKET_NAME_WITH_NOTIFICATIONS, test_key2
        )

        # receive, assert, and delete message from SQS
        self._receive_assert_delete(
            queue_url,
            [{"key": test_key2}, {"name": TEST_BUCKET_NAME_WITH_NOTIFICATIONS}],
            sqs_client,
        )

        # delete notification config
        self._delete_notification_config()

        # put notification config with single event type
        event = "s3:ObjectCreated:*"
        s3_client.put_bucket_notification_configuration(
            Bucket=TEST_BUCKET_NAME_WITH_NOTIFICATIONS,
            NotificationConfiguration={
                "QueueConfigurations": [
                    {"Id": "id123456", "QueueArn": queue_arn, "Events": [event]}
                ]
            },
        )
        config = s3_client.get_bucket_notification_configuration(
            Bucket=TEST_BUCKET_NAME_WITH_NOTIFICATIONS
        )
        config = config["QueueConfigurations"][0]
        self.assertEqual([event], config["Events"])

        # put notification config with single event type
        event = "s3:ObjectCreated:*"
        filter_rules = {"FilterRules": [{"Name": "Prefix", "Value": "testupload/"}]}
        s3_client.put_bucket_notification_configuration(
            Bucket=TEST_BUCKET_NAME_WITH_NOTIFICATIONS,
            NotificationConfiguration={
                "QueueConfigurations": [
                    {
                        "Id": "id123456",
                        "QueueArn": queue_arn,
                        "Events": [event],
                        "Filter": {"Key": filter_rules},
                    }
                ]
            },
        )
        config = s3_client.get_bucket_notification_configuration(
            Bucket=TEST_BUCKET_NAME_WITH_NOTIFICATIONS
        )
        config = config["QueueConfigurations"][0]
        self.assertEqual([event], config["Events"])
        self.assertEqual(filter_rules, config["Filter"]["Key"])

        # upload file to S3 (this should trigger a notification)
        test_key2 = "testupload/dir1/testfile.txt"
        test_data2 = b'{"test": "bucket_notification2"}'
        s3_client.upload_fileobj(
            BytesIO(test_data2), TEST_BUCKET_NAME_WITH_NOTIFICATIONS, test_key2
        )
        # receive, assert, and delete message from SQS
        self._receive_assert_delete(
            queue_url,
            [{"key": test_key2}, {"name": TEST_BUCKET_NAME_WITH_NOTIFICATIONS}],
            sqs_client,
        )

        # delete notification config
        self._delete_notification_config()

        #
        # Tests s3->sns->sqs notifications
        #
        sns_client = aws_stack.create_external_boto_client("sns")
        topic_info = sns_client.create_topic(Name=TEST_S3_TOPIC_NAME)

        s3_client.put_bucket_notification_configuration(
            Bucket=TEST_BUCKET_NAME_WITH_NOTIFICATIONS,
            NotificationConfiguration={
                "TopicConfigurations": [
                    {
                        "Id": "id123",
                        "Events": ["s3:ObjectCreated:*"],
                        "TopicArn": topic_info["TopicArn"],
                    }
                ]
            },
        )

        subscription_arn = sns_client.subscribe(
            TopicArn=topic_info["TopicArn"], Protocol="sqs", Endpoint=queue_arn
        )["SubscriptionArn"]

        test_key2 = "testupload/dir1/testfile.txt"
        test_data2 = b'{"test": "bucket_notification2"}'

        s3_client.upload_fileobj(
            BytesIO(test_data2), TEST_BUCKET_NAME_WITH_NOTIFICATIONS, test_key2
        )

        # verify subject and records
        def verify():
            response = sqs_client.receive_message(QueueUrl=queue_url)
            for message in response["Messages"]:
                sns_obj = json.loads(message["Body"])
                testutil.assert_object({"Subject": "Amazon S3 Notification"}, sns_obj)
                notification_obj = json.loads(sns_obj["Message"])
                testutil.assert_objects(
                    [{"key": test_key2}, {"name": TEST_BUCKET_NAME_WITH_NOTIFICATIONS}],
                    notification_obj["Records"],
                )

                sqs_client.delete_message(
                    QueueUrl=queue_url, ReceiptHandle=message["ReceiptHandle"]
                )

        retry(verify, retries=PUBLICATION_RETRIES, sleep=PUBLICATION_TIMEOUT)
        self._delete_notification_config()
        sns_client.unsubscribe(SubscriptionArn=subscription_arn)

    def _delete_notification_config(self):
        s3_client = aws_stack.create_external_boto_client("s3")
        s3_client.put_bucket_notification_configuration(
            Bucket=TEST_BUCKET_NAME_WITH_NOTIFICATIONS, NotificationConfiguration={}
        )
        config = s3_client.get_bucket_notification_configuration(
            Bucket=TEST_BUCKET_NAME_WITH_NOTIFICATIONS
        )
        self.assertFalse(config.get("QueueConfigurations"))
        self.assertFalse(config.get("TopicConfiguration"))

    def _receive_assert_delete(self, queue_url, assertions, sqs_client=None, required_subject=None):
        if not sqs_client:
            sqs_client = aws_stack.create_external_boto_client("sqs")

        response = sqs_client.receive_message(
            QueueUrl=queue_url, MessageAttributeNames=["All"], VisibilityTimeout=0
        )
        messages = []
        for m in response["Messages"]:
            message = json.loads(to_str(m["Body"]))
            message_attributes = m.get("MessageAttributes", {})
            message.update(message_attributes)
            messages.append(message)
        testutil.assert_objects(assertions, messages)
        for message in response["Messages"]:
            sqs_client.delete_message(QueueUrl=queue_url, ReceiptHandle=message["ReceiptHandle"])

    def create_test_queue(self):
        queue_name = "test-queue-%s" % short_uid()
        queue_url = self.sqs_client.create_queue(QueueName=queue_name)["QueueUrl"]
        queue_attributes = self.sqs_client.get_queue_attributes(
            QueueUrl=queue_url, AttributeNames=["QueueArn"]
        )
        return queue_url, queue_attributes

    def create_test_bucket(self):
        bucket_name = "test-bucket-%s" % short_uid()
        self.s3_client.create_bucket(Bucket=bucket_name)
        return bucket_name
