from localstack.config import LAMBDA_EVENT_SOURCE_MAPPING
from localstack.testing.aws.util import is_aws_cloud


def is_v2_esm():
    return LAMBDA_EVENT_SOURCE_MAPPING == "v2" and not is_aws_cloud()


def is_old_esm():
    return LAMBDA_EVENT_SOURCE_MAPPING == "v1" and not is_aws_cloud()
