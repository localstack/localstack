import re

from localstack import config
from localstack.aws.api import RequestContext
from localstack.aws.api.sts import GetCallerIdentityResponse, StsApi
from localstack.services.moto import call_moto
from localstack.services.plugins import ServiceLifecycleHook


class StsProvider(StsApi, ServiceLifecycleHook):
    def get_caller_identity(self, context: RequestContext) -> GetCallerIdentityResponse:
        result = call_moto(context)
        username = config.TEST_IAM_USER_NAME or "localstack"
        result = result.replace("user/moto", f"user/{username}")
        if config.TEST_IAM_USER_ID:
            search = r"(<UserId>)[^<]+(</UserId>)"
            replace = rf"\g<1>{config.TEST_IAM_USER_ID}\2"
            result = re.sub(search, replace, result, flags=re.MULTILINE)
        return result
