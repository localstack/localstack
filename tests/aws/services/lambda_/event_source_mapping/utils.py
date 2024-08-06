import os

from localstack.testing.aws.util import is_aws_cloud


def is_v2_esm():
    return os.environ.get("LAMBDA_EVENT_SOURCE_MAPPING") == "v2" and not is_aws_cloud()


def is_old_esm():
    return os.environ.get("LAMBDA_EVENT_SOURCE_MAPPING") == "v1" and not is_aws_cloud()
