import logging

from localstack.aws.api import CommonServiceException, RequestContext, handler
from localstack.aws.api.sts import (
    AssumeRoleResponse,
    GetCallerIdentityResponse,
    StsApi,
    arnType,
    externalIdType,
    policyDescriptorListType,
    roleDurationSecondsType,
    roleSessionNameType,
    serialNumberType,
    sessionPolicyDocumentType,
    sourceIdentityType,
    tagKeyListType,
    tagListType,
    tokenCodeType,
)
from localstack.aws.connect import connect_to
from localstack.services.moto import call_moto
from localstack.services.plugins import ServiceLifecycleHook

LOG = logging.getLogger(__name__)


class StsProvider(StsApi, ServiceLifecycleHook):
    @handler("AssumeRole")
    def assume_role(
        self,
        context: RequestContext,
        role_arn: arnType,
        role_session_name: roleSessionNameType,
        policy_arns: policyDescriptorListType = None,
        policy: sessionPolicyDocumentType = None,
        duration_seconds: roleDurationSecondsType = None,
        tags: tagListType = None,
        transitive_tag_keys: tagKeyListType = None,
        external_id: externalIdType = None,
        serial_number: serialNumberType = None,
        token_code: tokenCodeType = None,
        source_identity: sourceIdentityType = None,
    ) -> AssumeRoleResponse:
        role_account_id = role_arn.split(":")[4]
        role_name = role_arn.partition("/")[2]
        iam_client = connect_to(aws_access_key_id=role_account_id).iam

        if not role_name:
            self._raise_access_denied(context, role_arn)

        try:
            iam_client.get_role(RoleName=role_name)
        except iam_client.exceptions.NoSuchEntityException:
            self._raise_access_denied(context, role_arn)

        return call_moto(context)

    def get_caller_identity(self, context: RequestContext) -> GetCallerIdentityResponse:
        response = call_moto(context)
        if "user/moto" in response["Arn"] and "sts" in response["Arn"]:
            response["Arn"] = f"arn:aws:iam::{response['Account']}:root"
        return response

    def _raise_access_denied(self, context: RequestContext, resource: str) -> None:
        # TODO: replace `context.account_id` with proper principal arn
        raise CommonServiceException(
            code="AccessDenied",
            message=(
                f"User: {context.account_id} is not authorized to perform: "
                f"{context.service_operation.service}::{context.service_operation.operation} "
                f"on resource: {resource}"
            ),
            status_code=403,
        )
