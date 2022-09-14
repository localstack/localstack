import os

from localstack.aws.api.s3 import S3Api
from localstack.services.plugins import ServiceLifecycleHook

os.environ[
    "MOTO_S3_CUSTOM_ENDPOINTS"
] = "s3.localhost.localstack.cloud:4566,s3.localhost.localstack.cloud"


class S3Provider(S3Api, ServiceLifecycleHook):
    pass
