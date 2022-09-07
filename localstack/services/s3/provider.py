import os

from localstack.aws.api import RequestContext, handler
from localstack.aws.api.s3 import GetObjectOutput, GetObjectRequest, S3Api
from localstack.services.moto import call_moto
from localstack.services.plugins import ServiceLifecycleHook

os.environ[
    "MOTO_S3_CUSTOM_ENDPOINTS"
] = "s3.localhost.localstack.cloud:4566,s3.localhost.localstack.cloud"


class S3Provider(S3Api, ServiceLifecycleHook):
    @handler("GetObject", expand=False)
    def get_object(self, context: RequestContext, request: GetObjectRequest) -> GetObjectOutput:
        response = call_moto(context)
        response["AcceptRanges"] = "bytes"
        response["ContentType"] = "binary/octet-stream"
        return GetObjectOutput(**response)
