import pytest
from localstack_snapshot.snapshots import SnapshotSession
from localstack_snapshot.snapshots.transformer import RegexTransformer

from localstack.aws.api.lambda_ import (
    Runtime,
)
from localstack.testing.aws.lambda_utils import (
    _await_dynamodb_table_active,
)
from localstack.testing.snapshots.transformer_utility import (
    SNAPSHOT_BASIC_TRANSFORMER_NEW,
    TransformerUtility,
)
from localstack.utils.aws.arns import get_partition
from localstack.utils.strings import short_uid
from tests.aws.services.lambda_.test_lambda import (
    TEST_LAMBDA_PYTHON_ECHO,
)


# Here, we overwrite the snapshot fixture to allow the event_source_mapping subdir
# to use the newer basic transformer.
@pytest.fixture(scope="function")
def snapshot(request, _snapshot_session: SnapshotSession, account_id, region_name):
    _snapshot_session.transform = TransformerUtility

    _snapshot_session.add_transformer(RegexTransformer(account_id, "1" * 12), priority=2)
    _snapshot_session.add_transformer(RegexTransformer(region_name, "<region>"), priority=2)
    _snapshot_session.add_transformer(
        RegexTransformer(f"arn:{get_partition(region_name)}:", "arn:<partition>:"), priority=2
    )

    _snapshot_session.add_transformer(SNAPSHOT_BASIC_TRANSFORMER_NEW, priority=0)

    return _snapshot_session


@pytest.fixture(scope="function")
def sqs_standard_queue_arn(sqs_create_queue, sqs_get_queue_arn):
    """creates an sqs queue and returns the corresponding ARN"""

    queue_url = sqs_create_queue()
    queue_arn = sqs_get_queue_arn(queue_url)

    return queue_arn


@pytest.fixture(scope="function")
def kinesis_stream_arn(aws_client, kinesis_create_stream, wait_for_stream_ready):
    """creates a Kinesis stream and returns the corresponding ARN"""
    stream_name = f"stream-{short_uid()}"

    kinesis_create_stream(StreamName=stream_name, ShardCount=1)
    wait_for_stream_ready(stream_name=stream_name)

    stream_arn = aws_client.kinesis.describe_stream(StreamName=stream_name)["StreamDescription"][
        "StreamARN"
    ]

    return stream_arn


@pytest.fixture(scope="function")
def dynamodb_stream_arn(aws_client, dynamodb_create_table):
    """creates a DynamoDB table with an enabled stream and returns the corresponding ARN"""
    table_name = f"table-{short_uid()}"
    partition_key = "partition_key"

    dynamodb_create_table(table_name=table_name, partition_key=partition_key)
    _await_dynamodb_table_active(aws_client.dynamodb, table_name)

    update_table_response = aws_client.dynamodb.update_table(
        TableName=table_name,
        StreamSpecification={"StreamEnabled": True, "StreamViewType": "NEW_IMAGE"},
    )

    stream_arn = update_table_response["TableDescription"]["LatestStreamArn"]

    return stream_arn


@pytest.fixture(scope="function")
def lambda_function_name(create_lambda_function, aws_client):
    """creates an echo Lambda function and returns the corresponding name"""
    function_name = f"fn-{short_uid()}"
    create_lambda_function(
        handler_file=TEST_LAMBDA_PYTHON_ECHO,
        func_name=function_name,
        runtime=Runtime.python3_12,
    )

    return function_name
