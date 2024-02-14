import json

import pytest

from localstack.utils.sync import retry


@pytest.fixture
def read_s3_data(aws_client):
    s3 = aws_client.s3

    def _read_s3_data(bucket_name: str, timeout: int = 10) -> dict[str, str]:
        def _get_data():
            response = s3.list_objects(Bucket=bucket_name)
            if response.get("Contents") is None:
                raise Exception("No data in bucket yet")

            keys = [obj.get("Key") for obj in response.get("Contents")]

            bucket_data = dict()
            for key in keys:
                response = s3.get_object(Bucket=bucket_name, Key=key)
                data = response["Body"].read().decode("utf-8")
                bucket_data[key] = data
            return bucket_data

        bucket_data = retry(_get_data, sleep=1, retries=timeout)

        return bucket_data

    return _read_s3_data


@pytest.fixture
def get_all_messages_from_s3(read_s3_data):
    def _get_all_messages_from_s3(
        bucket_name: str,
        timeout: int = 300,
        sleep: int = 5,
        retries: int = 3,
        assert_message_count: int = 4,
    ) -> list[str]:
        # poll file from s3 buckets
        def get_all_messages():
            s3_data_bucket = read_s3_data(bucket_name, timeout=timeout)
            messages = []
            for input_string in s3_data_bucket.values():
                json_array_string = "[" + input_string.replace("}{", "},{") + "]"
                message = json.loads(json_array_string)
                messages.extend(message)
            if len(messages) != assert_message_count:
                raise Exception(f"Failed to receive all sent messages: {messages}")
            else:
                return messages

        messages = retry(get_all_messages, sleep=sleep, retries=retries)
        return messages

    yield _get_all_messages_from_s3
