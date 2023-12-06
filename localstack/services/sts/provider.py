import logging

from localstack.aws.api import RequestContext
from localstack.aws.api.sts import GetCallerIdentityResponse, StsApi
from localstack.services.moto import call_moto
from localstack.services.plugins import ServiceLifecycleHook

LOG = logging.getLogger(__name__)


class StsProvider(StsApi, ServiceLifecycleHook):
    def get_caller_identity(self, context: RequestContext) -> GetCallerIdentityResponse:
        response = call_moto(context)
        if "user/moto" in response["Arn"] and "sts" in response["Arn"]:
            response["Arn"] = f"arn:aws:iam::{response['Account']}:root"
        return response
