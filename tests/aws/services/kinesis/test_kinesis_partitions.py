import pytest

from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid


class TestKinesisPartitions:
    # We only have access to the AWS partition, not CHINA/US-GOV/etc
    @markers.aws.manual_setup_required
    @pytest.mark.parametrize(
        "region,partition",
        [("us-east-1", "aws"), ("cn-north-1", "aws-cn"), ("us-gov-east-1", "aws-us-gov")],
    )
    def test_stream_in_different_partitions(
        self, account_id, aws_client_factory, region, partition
    ):
        kinesis = aws_client_factory(region_name=region).kinesis

        stream_name = f"stream-{short_uid()}"
        kinesis.create_stream(StreamName=stream_name)

        stream = kinesis.describe_stream(StreamName=stream_name)["StreamDescription"]
        assert (
            stream["StreamARN"]
            == f"arn:{partition}:kinesis:{region}:{account_id}:stream/{stream_name}"
        )
