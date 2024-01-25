import logging
from typing import List, Literal, Union

import pytest

from localstack.utils.sync import retry

StreamType = Literal["DirectPut", "KinesisStreamAsSource", "MSKAsSource"]

LOG = logging.getLogger(__name__)


@pytest.fixture
def get_firehose_iam_documents():
    def _get_iam_document(
        bucket_arns: Union[List[str], str], stream_arns: Union[List[str], str]
    ) -> tuple[dict, dict]:
        if isinstance(bucket_arns, str):
            bucket_arns = [bucket_arns]
        bucket_arns.extend([f"{bucket_arn}/*" for bucket_arn in bucket_arns])
        if isinstance(stream_arns, str):
            stream_arns = [stream_arns]

        role_document = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "FirehoseAssumeRole",
                    "Effect": "Allow",
                    "Principal": {"Service": "firehose.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }

        policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "s3:AbortMultipartUpload",
                        "s3:GetBucketLocation",
                        "s3:GetObject",
                        "s3:ListBucket",
                        "s3:ListBucketMultipartUploads",
                        "s3:PutObject",
                    ],
                    "Resource": bucket_arns,
                },
                {
                    "Effect": "Allow",
                    "Action": [
                        "kinesis:DescribeStream",
                        "kinesis:GetShardIterator",
                        "kinesis:GetRecords",
                        "kinesis:ListShards",
                    ],
                    "Resource": stream_arns,
                },
                {
                    "Effect": "Allow",
                    "Action": ["logs:PutLogEvents", "logs:CreateLogStream"],
                    "Resource": "arn:aws:logs:*:*:*",
                },
            ],
        }
        return role_document, policy_document

    return _get_iam_document


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
