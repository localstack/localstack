import pytest

from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid


class TestSTSPartitions:
    # We only have access to the AWS partition, not CHINA/US-GOV/etc
    @markers.aws.manual_setup_required
    @pytest.mark.parametrize("region,partition", [("us-east-1", "aws"), ("cn-north-1", "aws-cn")])
    def test_sts_caller_identity_in_different_partitions(
        self, account_id, aws_client_factory, region, partition
    ):
        sts_client = aws_client_factory(region_name=region).sts

        assert sts_client.get_caller_identity()["Arn"] == f"arn:{partition}:iam::{account_id}:root"

    @markers.aws.manual_setup_required
    @pytest.mark.parametrize("region,partition", [("us-east-1", "aws"), ("cn-north-1", "aws-cn")])
    def test_caller_identity_with_custom_creds_in_different_partitions(
        self, account_id, aws_client_factory, region, partition
    ):
        iam_client = aws_client_factory(
            region_name=region, aws_access_key_id=f"random-{short_uid()}"
        ).iam
        user = iam_client.create_user(UserName=f"test-user-{short_uid()}")["User"]
        user_name = user["UserName"]

        access_key = iam_client.create_access_key(UserName=user_name)["AccessKey"]["AccessKeyId"]

        sts_user_client = aws_client_factory(region_name=region, aws_access_key_id=access_key).sts
        user_arn = sts_user_client.get_caller_identity()["Arn"]
        assert user_arn == f"arn:{partition}:iam::{account_id}:user/{user_name}"
