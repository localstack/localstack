import pytest

from localstack.testing.pytest import markers


class TestIamPartitions:
    # We only have access to the AWS partition, not CHINA/US-GOV/etc
    @markers.aws.manual_setup_required
    @pytest.mark.parametrize(
        "region,partition", [("us-east-2", "aws"), ("us-gov-east-1", "aws-us-gov")]
    )
    def test_service_linked_role_in_different_partitions(
        self, account_id, aws_client_factory, region, partition
    ):
        iam = aws_client_factory(region_name=region).iam

        arn = iam.create_service_linked_role(AWSServiceName="elasticbeanstalk")["Role"]["Arn"]
        assert arn.startswith(
            f"arn:{partition}:iam::{account_id}:role/aws-service-role/elasticbeanstalk/r-"
        )
