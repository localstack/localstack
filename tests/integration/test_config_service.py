import json

import pytest

from localstack.utils.common import short_uid

TEST_CONFIG_RECORDER_NAME = "test-recorder-name"
TEST_RESOURCE_TYPES = "AWS::EC2::Instance"
ASSUME_POLICY_DOCUMENT = {
    "Version": "2012-10-17",
    "Statement": [{"Action": "sts:AssumeRole", "Principal": {"Service": "lambda.amazonaws.com"}}],
}


class TestConfigService:
    @pytest.fixture
    def create_configuration_recorder(self, aws_client):
        def _create_config_recorder(iam_role_arn: str):
            aws_client.config.put_configuration_recorder(
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

        yield _create_config_recorder

    def test_put_configuration_recorder(
        self, aws_client, create_role, create_configuration_recorder
    ):
        iam_role_name = "role-{}".format(short_uid())
        iam_role_arn = create_role(
            RoleName=iam_role_name, AssumeRolePolicyDocument=json.dumps(ASSUME_POLICY_DOCUMENT)
        )["Role"]["Arn"]

        create_configuration_recorder(iam_role_arn)
        configuration_recorder_data = aws_client.config.describe_configuration_recorders()[
            "ConfigurationRecorders"
        ]

        assert TEST_CONFIG_RECORDER_NAME in configuration_recorder_data[0]["name"]
        assert iam_role_arn in configuration_recorder_data[0]["roleARN"]
        assert (
            TEST_RESOURCE_TYPES in configuration_recorder_data[0]["recordingGroup"]["resourceTypes"]
        )
        assert len(configuration_recorder_data) == 1

        aws_client.config.delete_configuration_recorder(
            ConfigurationRecorderName=TEST_CONFIG_RECORDER_NAME
        )

    def test_put_delivery_channel(
        self, aws_client, s3_create_bucket, create_role, create_configuration_recorder
    ):
        iam_role_name = "role-{}".format(short_uid())
        iam_role_arn = create_role(
            RoleName=iam_role_name, AssumeRolePolicyDocument=json.dumps(ASSUME_POLICY_DOCUMENT)
        )["Role"]["Arn"]

        create_configuration_recorder(iam_role_arn)

        test_bucket_name = f"test-bucket-{short_uid()}"
        s3_create_bucket(Bucket=test_bucket_name)

        sns_client = aws_client.sns
        sns_topic_arn = sns_client.create_topic(Name="test-sns-topic")["TopicArn"]

        delivery_channel_name = "test-delivery-channel"
        aws_client.config.put_delivery_channel(
            DeliveryChannel={
                "name": delivery_channel_name,
                "s3BucketName": test_bucket_name,
                "snsTopicARN": sns_topic_arn,
                "configSnapshotDeliveryProperties": {"deliveryFrequency": "Twelve_Hours"},
            }
        )

        delivery_channels = aws_client.config.describe_delivery_channels()["DeliveryChannels"]
        assert test_bucket_name in delivery_channels[0]["s3BucketName"]
        assert sns_topic_arn in delivery_channels[0]["snsTopicARN"]
        assert len(delivery_channels) == 1

        aws_client.config.delete_delivery_channel(DeliveryChannelName=delivery_channel_name)
        aws_client.config.delete_configuration_recorder(
            ConfigurationRecorderName=TEST_CONFIG_RECORDER_NAME
        )
