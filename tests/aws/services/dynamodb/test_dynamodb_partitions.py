import pytest

from localstack.testing.pytest import markers
from localstack.utils.aws.resources import create_dynamodb_table
from localstack.utils.strings import short_uid


class TestDynamoDBPartitions:
    # We only have access to the AWS partition, not CHINA/US-GOV/etc
    @markers.aws.manual_setup_required
    @pytest.mark.parametrize(
        "region,partition", [("us-east-2", "aws"), ("us-gov-east-1", "aws-us-gov")]
    )
    def test_dynamodb_table_in_different_partitions(
        self, account_id, aws_client_factory, region, partition
    ):
        dynamodb = aws_client_factory(region_name=region).dynamodb

        table_name = f"table-{short_uid()}"
        table = create_dynamodb_table(table_name, partition_key="id", client=dynamodb)
        table_arn = table["TableDescription"]["TableArn"]
        assert table_arn == f"arn:{partition}:dynamodb:{region}:{account_id}:table/{table_name}"

        table = dynamodb.describe_table(TableName=table_name)
        table_arn = table["Table"]["TableArn"]
        assert table_arn == f"arn:{partition}:dynamodb:{region}:{account_id}:table/{table_name}"
