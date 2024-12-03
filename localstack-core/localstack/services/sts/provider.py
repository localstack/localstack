import logging

from localstack.aws.api import RequestContext
from localstack.aws.api.sts import (
    AssumeRoleResponse,
    GetCallerIdentityResponse,
    ProvidedContextsListType,
    StsApi,
    arnType,
    externalIdType,
    policyDescriptorListType,
    roleDurationSecondsType,
    roleSessionNameType,
    serialNumberType,
    sourceIdentityType,
    tagKeyListType,
    tagListType,
    tokenCodeType,
    unrestrictedSessionPolicyDocumentType,
)
from localstack.services.iam.iam_patches import apply_iam_patches
from localstack.services.moto import call_moto
from localstack.services.plugins import ServiceLifecycleHook
from localstack.services.sts.models import sts_stores
from localstack.utils.aws.arns import extract_account_id_from_arn

LOG = logging.getLogger(__name__)


class StsProvider(StsApi, ServiceLifecycleHook):
    def __init__(self):
        apply_iam_patches()

    def get_caller_identity(self, context: RequestContext, **kwargs) -> GetCallerIdentityResponse:
        response = call_moto(context)
        if "user/moto" in response["Arn"] and "sts" in response["Arn"]:
            response["Arn"] = f"arn:{context.partition}:iam::{response['Account']}:root"
        return response

    def assume_role(
        self,
        context: RequestContext,
        role_arn: arnType,
        role_session_name: roleSessionNameType,
        policy_arns: policyDescriptorListType = None,
        policy: unrestrictedSessionPolicyDocumentType = None,
        duration_seconds: roleDurationSecondsType = None,
        tags: tagListType = None,
        transitive_tag_keys: tagKeyListType = None,
        external_id: externalIdType = None,
        serial_number: serialNumberType = None,
        token_code: tokenCodeType = None,
        source_identity: sourceIdentityType = None,
        provided_contexts: ProvidedContextsListType = None,
        **kwargs,
    ) -> AssumeRoleResponse:
        response: AssumeRoleResponse = call_moto(context)

        if tags:
            transformed_tags = {tag["Key"]: tag["Value"] for tag in tags}
            # we should save it in the store of the role account, not the requester
            account_id = extract_account_id_from_arn(role_arn)
            # the region is hardcoded to "us-east-1" as IAM/STS are global services
            # this will only differ for other partitions, which are not yet supported
            store = sts_stores[account_id]["us-east-1"]
            access_key_id = response["Credentials"]["AccessKeyId"]
            store.session_tags[access_key_id] = transformed_tags
        return response
