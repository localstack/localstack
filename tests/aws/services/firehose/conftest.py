import logging
from typing import Literal

import pytest

from localstack.utils.sync import retry

StreamType = Literal["DirectPut", "KinesisStreamAsSource", "MSKAsSource"]

LOG = logging.getLogger(__name__)


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
