import os

from localstack.config import LEGACY_V2_S3_PROVIDER

TEST_S3_IMAGE = os.path.exists("/usr/lib/localstack/.s3-version")


def is_v2_provider():
    return LEGACY_V2_S3_PROVIDER
