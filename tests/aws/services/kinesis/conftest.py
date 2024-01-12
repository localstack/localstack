import pytest

from localstack.utils.common import poll_condition


@pytest.fixture(autouse=True)
def kinesis_snapshot_transformer(snapshot):
    snapshot.add_transformer(snapshot.transform.kinesis_api())


@pytest.fixture
def wait_for_consumer_ready(aws_client):
    def _wait_for_consumer_ready(consumer_arn: str):
        def is_consumer_ready():
            describe_response = aws_client.kinesis.describe_stream_consumer(
                ConsumerARN=consumer_arn
            )
            return describe_response["ConsumerDescription"]["ConsumerStatus"] == "ACTIVE"

        poll_condition(is_consumer_ready)

    return _wait_for_consumer_ready
