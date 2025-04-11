import logging

from localstack.aws.api import RequestContext, ServiceException
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
from localstack.services.sts.models import SessionTaggingConfig, sts_stores
from localstack.utils.aws.arns import extract_account_id_from_arn
from localstack.utils.aws.request_context import extract_access_key_id_from_auth_header

LOG = logging.getLogger(__name__)


class InvalidParameterValueError(ServiceException):
    code = "InvalidParameterValue"
    status_code = 400
    sender_fault = True


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
        target_account_id = extract_account_id_from_arn(role_arn)
        access_key_id = extract_access_key_id_from_auth_header(context.request.headers)
        store = sts_stores[target_account_id]["us-east-1"]
        existing_tagging_config = store.session_tags.get(access_key_id, {})

        if tags:
            tag_keys = {tag["Key"].lower() for tag in tags}
            # if the lower-cased set is smaller than the number of keys, there have to be some duplicates.
            if len(tag_keys) < len(tags):
                raise InvalidParameterValueError(
                    "Duplicate tag keys found. Please note that Tag keys are case insensitive."
                )

            # prevent transitive tags from being overridden
            if existing_tagging_config:
                if set(existing_tagging_config["transitive_tags"]).intersection(tag_keys):
                    raise InvalidParameterValueError(
                        "One of the specified transitive tag keys can't be set because it conflicts with a transitive tag key from the calling session."
                    )
            if transitive_tag_keys:
                transitive_tag_key_set = {key.lower() for key in transitive_tag_keys}
                if not transitive_tag_key_set <= tag_keys:
                    raise InvalidParameterValueError(
                        "The specified transitive tag key must be included in the requested tags."
                    )

        response: AssumeRoleResponse = call_moto(context)

        transitive_tag_keys = transitive_tag_keys or []
        tags = tags or []
        transformed_tags = {tag["Key"].lower(): tag for tag in tags}
        # propagate transitive tags
        if existing_tagging_config:
            for tag in existing_tagging_config["transitive_tags"]:
                transformed_tags[tag] = existing_tagging_config["tags"][tag]
            transitive_tag_keys += existing_tagging_config["transitive_tags"]
        if transformed_tags:
            # store session tagging config
            access_key_id = response["Credentials"]["AccessKeyId"]
            store.session_tags[access_key_id] = SessionTaggingConfig(
                tags=transformed_tags,
                transitive_tags=[key.lower() for key in transitive_tag_keys],
            )
        return response
