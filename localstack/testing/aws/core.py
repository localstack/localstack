import os


def is_aws_cloud() -> bool:
    return os.environ.get("TEST_TARGET", "") == "AWS_CLOUD"
