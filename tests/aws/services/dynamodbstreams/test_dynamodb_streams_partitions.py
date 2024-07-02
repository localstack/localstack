import pytest

from localstack.testing.pytest import markers
from localstack.utils.aws.resources import create_dynamodb_table
from localstack.utils.strings import short_uid


class TestDynamoDBStreamsPartitions:
    # We only have access to the AWS partition, not CHINA/US-GOV/etc
    @markers.aws.manual_setup_required
    @pytest.mark.parametrize(
        "region,partition", [("us-east-2", "aws"), ("us-gov-east-1", "aws-us-gov")]
    )
    def test_dynamodb_stream_in_different_partitions(
        self, account_id, aws_client_factory, region, partition
    ):
        dynamodb = aws_client_factory(region_name=region).dynamodb
        dynamodbstreams = aws_client_factory(region_name=region).dynamodbstreams

        table_name = f"table-{short_uid()}"
        create_dynamodb_table(
            table_name, partition_key="id", stream_view_type="NEW_AND_OLD_IMAGES", client=dynamodb
        )

        table = dynamodb.describe_table(TableName=table_name)
        stream_arn = table["Table"]["LatestStreamArn"]
        assert stream_arn.startswith(
            f"arn:{partition}:dynamodb:{region}:{account_id}:table/{table_name}/stream/"
        )

        result = dynamodbstreams.describe_stream(StreamArn=stream_arn)["StreamDescription"]
        assert result["StreamArn"] == stream_arn
