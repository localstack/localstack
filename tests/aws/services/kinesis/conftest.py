import logging

import pytest

from localstack.utils.common import poll_condition

LOG = logging.getLogger(__name__)


@pytest.fixture
def register_kinesis_consumer(aws_client):
    kinesis = aws_client.kinesis
    consumer_arns = []

    def _register_kinesis_consumer(stream_arn: str, consumer_name: str):
        response = kinesis.register_stream_consumer(
            StreamARN=stream_arn, ConsumerName=consumer_name
        )
        consumer_arn = response["Consumer"]["ConsumerARN"]
        consumer_arns.append(consumer_arn)

        return consumer_arn

    yield _register_kinesis_consumer

    for consumer_arn in consumer_arns:
        try:
            kinesis.deregister_stream_consumer(ConsumerARN=consumer_arn)
        except Exception:
            LOG.info("Failed to deregister stream consumer %s", consumer_arn)


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
