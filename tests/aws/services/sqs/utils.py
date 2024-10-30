from typing import TYPE_CHECKING

from localstack.utils.sync import poll_condition

if TYPE_CHECKING:
    from mypy_boto3_sqs import SQSClient


def get_approx_number_of_messages(
    sqs_client: "SQSClient",
    queue_url: str,
) -> int:
    response = sqs_client.get_queue_attributes(
        QueueUrl=queue_url, AttributeNames=["ApproximateNumberOfMessages"]
    )
    return int(response["Attributes"]["ApproximateNumberOfMessages"])


def sqs_wait_queue_size(
    sqs_client: "SQSClient",
    queue_url: str,
    expected_num_messages: int,
    timeout: float = None,
) -> int:
    def _check_num_messages():
        return get_approx_number_of_messages(sqs_client, queue_url) >= expected_num_messages

    if not poll_condition(_check_num_messages, timeout=timeout):
        raise TimeoutError(
            f"gave up waiting for messages (expected={expected_num_messages}, "
            f"actual={get_approx_number_of_messages(sqs_client, queue_url)})"
        )

    return get_approx_number_of_messages(sqs_client, queue_url)
