from typing import TYPE_CHECKING

from localstack.utils.sync import poll_condition

if TYPE_CHECKING:
    from mypy_boto3_sqs import SQSClient
    from mypy_boto3_sqs.type_defs import MessageTypeDef


def sqs_collect_messages(
    sqs_client: "SQSClient",
    queue_url: str,
    expected: int,
    timeout: int,
    delete: bool = True,
    attribute_names: list[str] = None,
    message_attribute_names: list[str] = None,
) -> list["MessageTypeDef"]:
    collected = []

    def _receive():
        response = sqs_client.receive_message(
            QueueUrl=queue_url,
            # try not to wait too long, but also not poll too often
            WaitTimeSeconds=min(max(1, timeout), 5),
            MaxNumberOfMessages=1,
            AttributeNames=attribute_names or [],
            MessageAttributeNames=message_attribute_names or [],
        )

        if messages := response.get("Messages"):
            collected.extend(messages)

            if delete:
                for m in messages:
                    sqs_client.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])

        return len(collected) >= expected

    if not poll_condition(_receive, timeout=timeout):
        raise TimeoutError(
            f"gave up waiting for messages (expected={expected}, actual={len(collected)}"
        )

    return collected


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
