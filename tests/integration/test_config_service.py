import json
import unittest

from localstack.utils.aws import aws_stack
from localstack.utils.common import short_uid

TEST_CONFIG_RECORDER_NAME = "test-recorder-name"
TEST_RESOURCE_TYPES = "AWS::EC2::Instance"


class TestConfigService(unittest.TestCase):
    def setUp(self):
        self.config_service_client = aws_stack.create_external_boto_client("config")

    def create_iam_role(self, iam_role_name):
        self.iam_client = aws_stack.create_external_boto_client("iam")
        assume_policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {"Action": "sts:AssumeRole", "Principal": {"Service": "lambda.amazonaws.com"}}
            ],
        }

        iam_role_arn = self.iam_client.create_role(
            RoleName=iam_role_name,
            AssumeRolePolicyDocument=json.dumps(assume_policy_document),
        )["Role"]["Arn"]

        return iam_role_arn

    def create_configuration_recorder(self, iam_role_arn):
        self.config_service_client.put_configuration_recorder(
            ConfigurationRecorder={
                "name": TEST_CONFIG_RECORDER_NAME,
                "roleARN": iam_role_arn,
                "recordingGroup": {
                    "allSupported": False,
                    "includeGlobalResourceTypes": False,
                    "resourceTypes": [TEST_RESOURCE_TYPES],
                },
            }
        )

    def test_put_configuration_recorder(self):
        iam_role_name = "role-{}".format(short_uid())
        iam_role_arn = self.create_iam_role(iam_role_name)

        self.create_configuration_recorder(iam_role_arn)
        configuration_recorder_data = self.config_service_client.describe_configuration_recorders()[
            "ConfigurationRecorders"
        ]

        self.assertIn(TEST_CONFIG_RECORDER_NAME, configuration_recorder_data[0]["name"])
        self.assertIn(iam_role_arn, configuration_recorder_data[0]["roleARN"])
        self.assertIn(
            TEST_RESOURCE_TYPES, configuration_recorder_data[0]["recordingGroup"]["resourceTypes"]
        )
        self.assertEqual(1, len(configuration_recorder_data))

        self.config_service_client.delete_configuration_recorder(
            ConfigurationRecorderName=TEST_CONFIG_RECORDER_NAME
        )

    def test_put_delivery_channel(self):
        iam_role_name = "role-{}".format(short_uid())
        iam_role_arn = self.create_iam_role(iam_role_name)

        self.create_configuration_recorder(iam_role_arn)

        s3_client = aws_stack.create_external_boto_client("s3")
        test_bucket_name = f"test-bucket-{short_uid()}"
        s3_client.create_bucket(Bucket=test_bucket_name)

        sns_client = aws_stack.create_external_boto_client("sns")
        sns_topic_arn = sns_client.create_topic(Name="test-sns-topic")["TopicArn"]

        delivery_channel_name = "test-delivery-channel"
        self.config_service_client.put_delivery_channel(
            DeliveryChannel={
                "name": delivery_channel_name,
                "s3BucketName": test_bucket_name,
                "snsTopicARN": sns_topic_arn,
                "configSnapshotDeliveryProperties": {"deliveryFrequency": "Twelve_Hours"},
            }
        )

        delivery_channels = self.config_service_client.describe_delivery_channels()[
            "DeliveryChannels"
        ]
        self.assertIn(test_bucket_name, delivery_channels[0]["s3BucketName"])
        self.assertIn(sns_topic_arn, delivery_channels[0]["snsTopicARN"])
        self.assertEqual(1, len(delivery_channels))

        self.config_service_client.delete_delivery_channel(
            DeliveryChannelName=delivery_channel_name
        )
        self.config_service_client.delete_configuration_recorder(
            ConfigurationRecorderName=TEST_CONFIG_RECORDER_NAME
        )
