import json
import logging

from localstack.utils.sync import retry

LOG = logging.getLogger(__name__)


def read_s3_data(aws_client, bucket_name: str) -> dict[str, str]:
    response = aws_client.s3.list_objects(Bucket=bucket_name)
    if response.get("Contents") is None:
        raise Exception("No data in bucket yet")

    keys = [obj.get("Key") for obj in response.get("Contents")]

    bucket_data = dict()
    for key in keys:
        response = aws_client.s3.get_object(Bucket=bucket_name, Key=key)
        data = response["Body"].read().decode("utf-8")
        bucket_data[key] = data
    return bucket_data


def get_all_expected_messages_from_s3(
    aws_client,
    bucket_name: str,
    sleep: int = 5,
    retries: int = 3,
    expected_message_count: int | None = None,
) -> list[str]:
    def get_all_messages():
        bucket_data = read_s3_data(aws_client, bucket_name)
        messages = []
        for input_string in bucket_data.values():
            json_array_string = "[" + input_string.replace("}{", "},{") + "]"
            message = json.loads(json_array_string)
            LOG.debug("Received messages: %s", message)
            messages.extend(message)
        if expected_message_count is not None and len(messages) != expected_message_count:
            raise Exception(f"Failed to receive all sent messages: {messages}")
        else:
            return messages

    all_messages = retry(get_all_messages, sleep=sleep, retries=retries)
    return all_messages
