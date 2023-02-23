import logging

from localstack.aws.api import RequestContext
from localstack.aws.api.sts import GetCallerIdentityResponse, StsApi
from localstack.services.moto import call_moto
from localstack.services.plugins import ServiceLifecycleHook
from localstack.utils.aws.arns import get_partition

LOG = logging.getLogger(__name__)


class StsProvider(StsApi, ServiceLifecycleHook):
    def get_caller_identity(self, context: RequestContext) -> GetCallerIdentityResponse:
        result = call_moto(context)
        if "user/moto" in result["Arn"] and "sts" in result["Arn"]:
            result["Arn"] = f"arn:{get_partition(context.region)}:iam::{result['Account']}:root"
        return result
