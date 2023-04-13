import logging

from localstack import config
from localstack.aws.api import RequestContext, handler
from localstack.aws.api.sts import (
    AssumeRoleRequest,
    AssumeRoleResponse,
    GetCallerIdentityResponse,
    StsApi,
)
from localstack.services.moto import call_moto
from localstack.services.plugins import ServiceLifecycleHook

LOG = logging.getLogger(__name__)


class StsProvider(StsApi, ServiceLifecycleHook):
    def get_caller_identity(self, context: RequestContext) -> GetCallerIdentityResponse:
        response = call_moto(context)
        if "user/moto" in response["Arn"] and "sts" in response["Arn"]:
            response["Arn"] = f"arn:aws:iam::{response['Account']}:root"
        return response

    @handler("AssumeRole", expand=False)
    def assume_role(
        self, context: RequestContext, request: AssumeRoleRequest
    ) -> AssumeRoleResponse:
        response = call_moto(context)
        if not config.PARITY_AWS_ACCESS_KEY_ID and (
            access_key_id := response.get("Credentials", {}).get("AccessKeyId")
        ):
            response["Credentials"]["AccessKeyId"] = "L" + access_key_id[1:]
        return response
