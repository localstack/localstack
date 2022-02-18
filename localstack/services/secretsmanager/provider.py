import json
import logging

from localstack.aws.api import HttpRequest, RequestContext
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
from localstack.services.moto import call_moto
from localstack.services.secretsmanager.secretsmanager_patches import apply_patches
from localstack.utils.aws import aws_stack
from localstack.utils.common import to_str

LOG = logging.getLogger(__name__)


class SecretsmanagerProvider(SecretsmanagerApi):
    def __init__(self):
        apply_patches()  # Adds missing moto attributes.

    @staticmethod
    def __transform_context_secret_id(context: RequestContext) -> RequestContext:
        data_dict = json.loads(to_str(context.request.data or "{}"))
        secret_id = data_dict.get("SecretId", "")
        if ":" in secret_id:
            request = context.request
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
                data_dict["SecretId"] = parts[-1][: len(parts[-1]) - 7]
            elif parts[-1][-1] != "-":
                data_dict["SecretId"] = data_dict["SecretId"] + "-"
            #
            context.request = HttpRequest(
                method=request.method,
                path=request.path,
                query_string=request.query_string,
                headers=request.headers,
                body=bytes(json.dumps(data_dict), "utf-8"),
            )
        return context

    def cancel_rotate_secret(
        self, context: RequestContext, secret_id: SecretIdType
    ) -> CancelRotateSecretResponse:
        return CreateSecretResponse(**call_moto(self.__transform_context_secret_id(context)))

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
        return CreateSecretResponse(**call_moto(self.__transform_context_secret_id(context)))

    def delete_resource_policy(
        self, context: RequestContext, secret_id: SecretIdType
    ) -> DeleteResourcePolicyResponse:
        return DeleteResourcePolicyResponse(
            **call_moto(self.__transform_context_secret_id(context))
        )

    def delete_secret(
        self,
        context: RequestContext,
        secret_id: SecretIdType,
        recovery_window_in_days: RecoveryWindowInDaysType = None,
        force_delete_without_recovery: BooleanType = None,
    ) -> DeleteSecretResponse:
        return DeleteSecretResponse(**call_moto(self.__transform_context_secret_id(context)))

    def describe_secret(
        self, context: RequestContext, secret_id: SecretIdType
    ) -> DescribeSecretResponse:
        return DescribeSecretResponse(**call_moto(self.__transform_context_secret_id(context)))

    def get_resource_policy(
        self, context: RequestContext, secret_id: SecretIdType
    ) -> GetResourcePolicyResponse:
        return GetResourcePolicyResponse(**call_moto(self.__transform_context_secret_id(context)))

    def get_secret_value(
        self,
        context: RequestContext,
        secret_id: SecretIdType,
        version_id: SecretVersionIdType = None,
        version_stage: SecretVersionStageType = None,
    ) -> GetSecretValueResponse:
        return GetSecretValueResponse(**call_moto(self.__transform_context_secret_id(context)))

    def list_secret_version_ids(
        self,
        context: RequestContext,
        secret_id: SecretIdType,
        max_results: MaxResultsType = None,
        next_token: NextTokenType = None,
        include_deprecated: BooleanType = None,
    ) -> ListSecretVersionIdsResponse:
        return ListSecretVersionIdsResponse(
            **call_moto(self.__transform_context_secret_id(context))
        )

    def put_resource_policy(
        self,
        context: RequestContext,
        secret_id: SecretIdType,
        resource_policy: NonEmptyResourcePolicyType,
        block_public_policy: BooleanType = None,
    ) -> PutResourcePolicyResponse:
        return PutResourcePolicyResponse(**call_moto(self.__transform_context_secret_id(context)))

    def put_secret_value(
        self,
        context: RequestContext,
        secret_id: SecretIdType,
        client_request_token: ClientRequestTokenType = None,
        secret_binary: SecretBinaryType = None,
        secret_string: SecretStringType = None,
        version_stages: SecretVersionStagesType = None,
    ) -> PutSecretValueResponse:
        return PutSecretValueResponse(**call_moto(self.__transform_context_secret_id(context)))

    def remove_regions_from_replication(
        self,
        context: RequestContext,
        secret_id: SecretIdType,
        remove_replica_regions: RemoveReplicaRegionListType,
    ) -> RemoveRegionsFromReplicationResponse:
        return RemoveRegionsFromReplicationResponse(
            **call_moto(self.__transform_context_secret_id(context))
        )

    def replicate_secret_to_regions(
        self,
        context: RequestContext,
        secret_id: SecretIdType,
        add_replica_regions: AddReplicaRegionListType,
        force_overwrite_replica_secret: BooleanType = None,
    ) -> ReplicateSecretToRegionsResponse:
        return ReplicateSecretToRegionsResponse(
            **call_moto(self.__transform_context_secret_id(context))
        )

    def restore_secret(
        self, context: RequestContext, secret_id: SecretIdType
    ) -> RestoreSecretResponse:
        return RestoreSecretResponse(**call_moto(self.__transform_context_secret_id(context)))

    def rotate_secret(
        self,
        context: RequestContext,
        secret_id: SecretIdType,
        client_request_token: ClientRequestTokenType = None,
        rotation_lambda_arn: RotationLambdaARNType = None,
        rotation_rules: RotationRulesType = None,
        rotate_immediately: BooleanType = None,
    ) -> RotateSecretResponse:
        return RotateSecretResponse(**call_moto(self.__transform_context_secret_id(context)))

    def stop_replication_to_replica(
        self, context: RequestContext, secret_id: SecretIdType
    ) -> StopReplicationToReplicaResponse:
        return StopReplicationToReplicaResponse(
            **call_moto(self.__transform_context_secret_id(context))
        )

    def tag_resource(
        self, context: RequestContext, secret_id: SecretIdType, tags: TagListType
    ) -> None:
        call_moto(self.__transform_context_secret_id(context))

    def untag_resource(
        self, context: RequestContext, secret_id: SecretIdType, tag_keys: TagKeyListType
    ) -> None:
        call_moto(self.__transform_context_secret_id(context))

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
        return UpdateSecretResponse(**call_moto(self.__transform_context_secret_id(context)))

    def update_secret_version_stage(
        self,
        context: RequestContext,
        secret_id: SecretIdType,
        version_stage: SecretVersionStageType,
        remove_from_version_id: SecretVersionIdType = None,
        move_to_version_id: SecretVersionIdType = None,
    ) -> UpdateSecretVersionStageResponse:
        return UpdateSecretVersionStageResponse(
            **call_moto(self.__transform_context_secret_id(context))
        )

    def validate_resource_policy(
        self,
        context: RequestContext,
        resource_policy: NonEmptyResourcePolicyType,
        secret_id: SecretIdType = None,
    ) -> ValidateResourcePolicyResponse:
        return ValidateResourcePolicyResponse(
            **call_moto(self.__transform_context_secret_id(context))
        )
