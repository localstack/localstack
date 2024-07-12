from typing import Union


def get_firehose_iam_documents(
    bucket_arns: Union[list[str], str], stream_arns: Union[list[str], str]
) -> tuple[dict, dict]:
    """
    Generate the required IAM role and policy documents for Firehose.
    """
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
