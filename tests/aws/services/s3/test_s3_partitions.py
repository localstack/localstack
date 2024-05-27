import pytest

from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid


class TestS3Partitions:
    # We only have access to the AWS partition, not CHINA/US-GOV/etc
    @markers.aws.manual_setup_required
    @pytest.mark.parametrize("region,partition", [("us-east-2", "aws"), ("cn-north-1", "aws-cn")])
    def test_sns_notifications_in_different_partitions(
        self, account_id, aws_client_factory, region, partition
    ):
        s3 = aws_client_factory(region_name=region).s3
        sns = aws_client_factory(region_name=region).sns

        topic_name = f"topic-{short_uid()}"
        topic_arn = sns.create_topic(Name=topic_name)["TopicArn"]

        bucket_name = f"test-bucket-{short_uid()}"
        s3.create_bucket(
            Bucket=bucket_name, CreateBucketConfiguration={"LocationConstraint": region}
        )

        s3.put_bucket_notification_configuration(
            Bucket=bucket_name,
            NotificationConfiguration={
                "TopicConfigurations": [
                    {
                        "TopicArn": topic_arn,
                        "Events": ["s3:ObjectCreated:*"],
                    }
                ]
            },
        )

        resp = s3.get_bucket_notification_configuration(Bucket=bucket_name)
        assert resp["TopicConfigurations"][0]["TopicArn"] == topic_arn
