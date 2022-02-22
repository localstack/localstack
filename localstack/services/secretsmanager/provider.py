import json
import logging
from abc import ABC
from typing import Optional

from localstack.aws.api import RequestContext, ServiceResponse
from localstack.aws.api.secretsmanager import (
    AddReplicaRegionListType,
    BooleanType,
    CancelRotateSecretResponse,
    ClientRequestTokenType,
    CreateSecretResponse,
    DeleteResourcePolicyResponse,
    DeleteSecretResponse,
    DescribeSecretResponse,
    DescriptionType,
    GetResourcePolicyResponse,
    GetSecretValueResponse,
    KmsKeyIdType,
    ListSecretVersionIdsResponse,
    MaxResultsType,
    NameType,
    NextTokenType,
    NonEmptyResourcePolicyType,
    PutResourcePolicyResponse,
    PutSecretValueResponse,
    RecoveryWindowInDaysType,
    RemoveRegionsFromReplicationResponse,
    RemoveReplicaRegionListType,
    ReplicateSecretToRegionsResponse,
    RestoreSecretResponse,
    RotateSecretResponse,
    RotationLambdaARNType,
    RotationRulesType,
    SecretBinaryType,
    SecretIdType,
    SecretsmanagerApi,
    SecretStringType,
    SecretVersionIdType,
    SecretVersionStagesType,
    SecretVersionStageType,
    StopReplicationToReplicaResponse,
    TagKeyListType,
    TagListType,
    UpdateSecretResponse,
    UpdateSecretVersionStageResponse,
    ValidateResourcePolicyResponse,
)
from localstack.services.moto import call_moto, call_moto_with_request
from localstack.services.secretsmanager.secretsmanager_patches import apply_patches
from localstack.utils.aws import aws_stack
from localstack.utils.common import to_str

LOG = logging.getLogger(__name__)


class SecretsmanagerProvider(SecretsmanagerApi, ABC):
    def __init__(self):
        apply_patches()  # Adds missing moto attributes.

    @staticmethod
    def _transform_context_secret_id(context: RequestContext) -> Optional[dict]:
        data_dict = json.loads(to_str(context.request.data or "{}"))
        secret_id = data_dict.get("SecretId", None)
        if secret_id and ":" in secret_id:
            parts = secret_id.split(":")
            if parts[3] != aws_stack.get_region():
                LOG.info(
                    'Unexpected request region %s for secret "%s"',
                    aws_stack.get_region(),
                    secret_id,
                )
            # secret ARN ends with "-<randomId>" which we remove in the request for upstream compatibility
            # if the full arn is being sent then we remove the string in the end
            if parts[-1][-7] == "-":
                secret_id = parts[-1][: len(parts[-1]) - 7]
            elif parts[-1][-1] != "-":
                secret_id = secret_id + "-"
            #
            data_dict["SecretId"] = secret_id
            return data_dict
        return None

    @staticmethod
    def _call_moto_with_request_secret_id(context: RequestContext) -> ServiceResponse:
        data_dict = SecretsmanagerProvider._transform_context_secret_id(context)
        return call_moto_with_request(context, data_dict) if data_dict else call_moto(context)

    def cancel_rotate_secret(
        self, context: RequestContext, secret_id: SecretIdType
    ) -> CancelRotateSecretResponse:
        return CreateSecretResponse(**self._call_moto_with_request_secret_id(context))

    def create_secret(
        self,
        context: RequestContext,
        name: NameType,
        client_request_token: ClientRequestTokenType = None,
        description: DescriptionType = None,
        kms_key_id: KmsKeyIdType = None,
        secret_binary: SecretBinaryType = None,
        secret_string: SecretStringType = None,
        tags: TagListType = None,
        add_replica_regions: AddReplicaRegionListType = None,
        force_overwrite_replica_secret: BooleanType = None,
    ) -> CreateSecretResponse:
        return CreateSecretResponse(**self._call_moto_with_request_secret_id(context))

    def delete_resource_policy(
        self, context: RequestContext, secret_id: SecretIdType
    ) -> DeleteResourcePolicyResponse:
        return DeleteResourcePolicyResponse(**self._call_moto_with_request_secret_id(context))

    def delete_secret(
        self,
        context: RequestContext,
        secret_id: SecretIdType,
        recovery_window_in_days: RecoveryWindowInDaysType = None,
        force_delete_without_recovery: BooleanType = None,
    ) -> DeleteSecretResponse:
        return DeleteSecretResponse(**self._call_moto_with_request_secret_id(context))

    def describe_secret(
        self, context: RequestContext, secret_id: SecretIdType
    ) -> DescribeSecretResponse:
        return DescribeSecretResponse(**self._call_moto_with_request_secret_id(context))

    def get_resource_policy(
        self, context: RequestContext, secret_id: SecretIdType
    ) -> GetResourcePolicyResponse:
        return GetResourcePolicyResponse(**self._call_moto_with_request_secret_id(context))

    def get_secret_value(
        self,
        context: RequestContext,
        secret_id: SecretIdType,
        version_id: SecretVersionIdType = None,
        version_stage: SecretVersionStageType = None,
    ) -> GetSecretValueResponse:
        return GetSecretValueResponse(**self._call_moto_with_request_secret_id(context))

    def list_secret_version_ids(
        self,
        context: RequestContext,
        secret_id: SecretIdType,
        max_results: MaxResultsType = None,
        next_token: NextTokenType = None,
        include_deprecated: BooleanType = None,
    ) -> ListSecretVersionIdsResponse:
        return ListSecretVersionIdsResponse(**self._call_moto_with_request_secret_id(context))

    def put_resource_policy(
        self,
        context: RequestContext,
        secret_id: SecretIdType,
        resource_policy: NonEmptyResourcePolicyType,
        block_public_policy: BooleanType = None,
    ) -> PutResourcePolicyResponse:
        return PutResourcePolicyResponse(**self._call_moto_with_request_secret_id(context))

    def put_secret_value(
        self,
        context: RequestContext,
        secret_id: SecretIdType,
        client_request_token: ClientRequestTokenType = None,
        secret_binary: SecretBinaryType = None,
        secret_string: SecretStringType = None,
        version_stages: SecretVersionStagesType = None,
    ) -> PutSecretValueResponse:
        return PutSecretValueResponse(**self._call_moto_with_request_secret_id(context))

    def remove_regions_from_replication(
        self,
        context: RequestContext,
        secret_id: SecretIdType,
        remove_replica_regions: RemoveReplicaRegionListType,
    ) -> RemoveRegionsFromReplicationResponse:
        return RemoveRegionsFromReplicationResponse(
            **self._call_moto_with_request_secret_id(context)
        )

    def replicate_secret_to_regions(
        self,
        context: RequestContext,
        secret_id: SecretIdType,
        add_replica_regions: AddReplicaRegionListType,
        force_overwrite_replica_secret: BooleanType = None,
    ) -> ReplicateSecretToRegionsResponse:
        return ReplicateSecretToRegionsResponse(**self._call_moto_with_request_secret_id(context))

    def restore_secret(
        self, context: RequestContext, secret_id: SecretIdType
    ) -> RestoreSecretResponse:
        return RestoreSecretResponse(**self._call_moto_with_request_secret_id(context))

    def rotate_secret(
        self,
        context: RequestContext,
        secret_id: SecretIdType,
        client_request_token: ClientRequestTokenType = None,
        rotation_lambda_arn: RotationLambdaARNType = None,
        rotation_rules: RotationRulesType = None,
        rotate_immediately: BooleanType = None,
    ) -> RotateSecretResponse:
        return RotateSecretResponse(**self._call_moto_with_request_secret_id(context))

    def stop_replication_to_replica(
        self, context: RequestContext, secret_id: SecretIdType
    ) -> StopReplicationToReplicaResponse:
        return StopReplicationToReplicaResponse(**self._call_moto_with_request_secret_id(context))

    def tag_resource(
        self, context: RequestContext, secret_id: SecretIdType, tags: TagListType
    ) -> None:
        self._call_moto_with_request_secret_id(context)

    def untag_resource(
        self, context: RequestContext, secret_id: SecretIdType, tag_keys: TagKeyListType
    ) -> None:
        self._call_moto_with_request_secret_id(context)

    def update_secret(
        self,
        context: RequestContext,
        secret_id: SecretIdType,
        client_request_token: ClientRequestTokenType = None,
        description: DescriptionType = None,
        kms_key_id: KmsKeyIdType = None,
        secret_binary: SecretBinaryType = None,
        secret_string: SecretStringType = None,
    ) -> UpdateSecretResponse:
        return UpdateSecretResponse(**self._call_moto_with_request_secret_id(context))

    def update_secret_version_stage(
        self,
        context: RequestContext,
        secret_id: SecretIdType,
        version_stage: SecretVersionStageType,
        remove_from_version_id: SecretVersionIdType = None,
        move_to_version_id: SecretVersionIdType = None,
    ) -> UpdateSecretVersionStageResponse:
        return UpdateSecretVersionStageResponse(**self._call_moto_with_request_secret_id(context))

    def validate_resource_policy(
        self,
        context: RequestContext,
        resource_policy: NonEmptyResourcePolicyType,
        secret_id: SecretIdType = None,
    ) -> ValidateResourcePolicyResponse:
        return ValidateResourcePolicyResponse(**self._call_moto_with_request_secret_id(context))
