import copy
import json
from collections import defaultdict, namedtuple
from typing import Callable

import pytest
from localstack_snapshot.snapshots import SnapshotSession
from localstack_snapshot.snapshots.transformer import RegexTransformer

from localstack.aws.api.lambda_ import Runtime
from localstack.testing.aws.util import is_aws_cloud
from localstack.testing.snapshots.transformer_utility import (
    SNAPSHOT_BASIC_TRANSFORMER_NEW,
    TransformerUtility,
)
from localstack.utils.aws.arns import get_partition
from localstack.utils.strings import short_uid
from tests.aws.services.lambda_.test_lambda import (
    TEST_LAMBDA_EVENT_SOURCE_MAPPING_SEND_MESSAGE,
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
def create_function_with_sqs_destination(
    create_lambda_function,
    sqs_create_queue,
    lambda_su_role,
):
    destination_queue_name = f"destination-queue-{short_uid()}"
    function_name = f"function-{short_uid()}"
    FixtureResults = namedtuple("FixtureResults", ["function_name", "sqs_queue_url"])

    def _create_function(**kwargs) -> FixtureResults:
        create_function_kwargs = {
            "runtime": Runtime.python3_12,
            "role": lambda_su_role,
            "func_name": function_name,
        }

        create_function_kwargs.update(kwargs)

        destination_queue_url = sqs_create_queue(QueueName=destination_queue_name)
        envvars = {
            "SQS_QUEUE_URL": destination_queue_url,
        }
        if is_aws_cloud():
            envvars["AWS_CLOUD"] = "1"

        create_lambda_function(
            handler_file=TEST_LAMBDA_EVENT_SOURCE_MAPPING_SEND_MESSAGE,
            envvars=envvars,
            **create_function_kwargs,
        )

        return FixtureResults(
            function_name=create_function_kwargs["func_name"], sqs_queue_url=destination_queue_url
        )

    return _create_function


@pytest.fixture(scope="function")
def get_msg_from_q(aws_client) -> Callable[[str, int], dict[str, list]]:
    invocation_batches = defaultdict(list)

    def _receive_and_delete(destination_queue_url: str, expected_size: int) -> dict[str, list]:
        messages_to_delete = []
        receive_message_response = aws_client.sqs.receive_message(
            QueueUrl=destination_queue_url,
            MaxNumberOfMessages=10,
            VisibilityTimeout=120,
            WaitTimeSeconds=20 if is_aws_cloud() else 1,
            MessageAttributeNames=["All"],
        )
        messages = receive_message_response.get("Messages", [])
        if messages:
            for message in messages:
                received_batch = json.loads(message["Body"])

                invocation_id = message["MessageAttributes"]["lambda_execution_id"]
                invocation_batches[invocation_id["StringValue"]].append(received_batch)

                messages_to_delete.append(
                    {"Id": message["MessageId"], "ReceiptHandle": message["ReceiptHandle"]}
                )

            aws_client.sqs.delete_message_batch(
                QueueUrl=destination_queue_url, Entries=messages_to_delete
            )

        total_items = sum(
            [sum(len(batch) for batch in batches) for batches in invocation_batches.values()]
        )
        assert total_items == expected_size

        result = dict(copy.deepcopy(invocation_batches))
        invocation_batches.clear()
        return result

    return _receive_and_delete
