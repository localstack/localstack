import json

import pytest

from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid


class TestSqsPartitions:
    # We only have access to the AWS partition, not CHINA/US-GOV/etc
    @markers.aws.manual_setup_required
    @pytest.mark.parametrize("region,partition", [("us-east-2", "aws"), ("cn-north-1", "aws-cn")])
    def test_queue_in_different_partitions(self, account_id, aws_client_factory, region, partition):
        sqs = aws_client_factory(region_name=region).sqs

        queue_name = f"queue_{short_uid()}"
        queue_url = sqs.create_queue(QueueName=queue_name)["QueueUrl"]
        queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])[
            "Attributes"
        ]["QueueArn"]
        assert queue_arn == f"arn:{partition}:sqs:{region}:{account_id}:{queue_name}"

    @markers.aws.manual_setup_required
    @pytest.mark.parametrize("region,partition", [("us-east-2", "aws"), ("cn-north-1", "aws-cn")])
    def test_permission_in_different_partitions(
        self, account_id, aws_client_factory, region, partition
    ):
        sqs = aws_client_factory(region_name=region).sqs

        queue_name = f"queue_{short_uid()}"
        queue_url = sqs.create_queue(QueueName=queue_name)["QueueUrl"]

        sqs.add_permission(
            QueueUrl=queue_url, Label="Yes", AWSAccountIds=[account_id], Actions=["*"]
        )

        policy = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["All"])["Attributes"][
            "Policy"
        ]
        policy = json.loads(policy)
        assert (
            policy["Id"]
            == f"arn:{partition}:sqs:{region}:{account_id}:{queue_name}/SQSDefaultPolicy"
        )
        assert (
            policy["Statement"][0]["Principal"]["AWS"] == f"arn:{partition}:iam::{account_id}:root"
        )
