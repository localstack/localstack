import os

from localstack.testing.aws.util import is_aws_cloud


def is_v2_provider():
    return os.environ.get("PROVIDER_OVERRIDE_EVENTS") == "v2" and not is_aws_cloud()
