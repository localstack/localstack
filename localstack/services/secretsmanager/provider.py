import json
import random
import string

from moto.iam.policy_validation import IAMPolicyDocumentValidator
from moto.secretsmanager import models as secretsmanager_models
from moto.secretsmanager.exceptions import SecretNotFoundException
from moto.secretsmanager.models import SecretsManagerBackend, secretsmanager_backends
from moto.secretsmanager.responses import SecretsManagerResponse

from localstack.aws.api import RequestContext
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
    ExcludeCharactersType,
    ExcludeLowercaseType,
    ExcludeNumbersType,
    ExcludePunctuationType,
    ExcludeUppercaseType,
    FiltersListType,
    GetRandomPasswordResponse,
    GetResourcePolicyResponse,
    GetSecretValueResponse,
    IncludeSpaceType,
    KmsKeyIdType,
    ListSecretsResponse,
    ListSecretVersionIdsResponse,
    MaxResultsType,
    NameType,
    NextTokenType,
    NonEmptyResourcePolicyType,
    PasswordLengthType,
    PutResourcePolicyResponse,
    PutSecretValueResponse,
    RecoveryWindowInDaysType,
    RemoveRegionsFromReplicationResponse,
    RemoveReplicaRegionListType,
    ReplicateSecretToRegionsResponse,
    RequireEachIncludedTypeType,
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
    SortOrderType,
    StopReplicationToReplicaResponse,
    TagKeyListType,
    TagListType,
    UpdateSecretResponse,
    UpdateSecretVersionStageResponse,
    ValidateResourcePolicyResponse,
)
from localstack.constants import TEST_AWS_ACCOUNT_ID
from localstack.services.moto import call_moto


class SecretsmanagerProvider(SecretsmanagerApi):
    def __init__(self):
        # maps key names to ARNs
        self.SECRET_ARN_STORAGE = {}
        #
        self.__apply_patches()

    def __apply_patches(self):
        def secretsmanager_models_secret_arn(region, secret_id):
            k = "{}_{}".format(region, secret_id)
            if k not in self.SECRET_ARN_STORAGE:
                id_string = "".join(random.choice(string.ascii_letters) for _ in range(6))
                arn = "arn:aws:secretsmanager:{0}:{1}:secret:{2}-{3}".format(
                    region, TEST_AWS_ACCOUNT_ID, secret_id, id_string
                )
                self.SECRET_ARN_STORAGE[k] = arn

            return self.SECRET_ARN_STORAGE[k]

        secretsmanager_models.secret_arn = secretsmanager_models_secret_arn

        # patching resource policy in moto
        def get_resource_policy_model(self, secret_id):
            if self._is_valid_identifier(secret_id):
                result = {
                    "ARN": self.secrets[secret_id].arn,
                    "Name": self.secrets[secret_id].secret_id,
                }

                policy = getattr(self.secrets[secret_id], "policy", None)
                if policy:
                    result["ResourcePolicy"] = json.dumps(policy)

                return json.dumps(result)
            else:
                raise SecretNotFoundException()

        setattr(SecretsManagerBackend, "get_resource_policy", get_resource_policy_model)

        def get_resource_policy_response(self):
            secret_id = self._get_param("SecretId")
            return secretsmanager_backends[self.region].get_resource_policy(secret_id=secret_id)

        setattr(SecretsManagerResponse, "get_resource_policy", get_resource_policy_response)

        def delete_resource_policy_model(self, secret_id):
            if self._is_valid_identifier(secret_id):
                self.secrets[secret_id].policy = None
                return json.dumps(
                    {
                        "ARN": self.secrets[secret_id].arn,
                        "Name": self.secrets[secret_id].secret_id,
                    }
                )
            else:
                raise SecretNotFoundException()

        if not hasattr(SecretsManagerBackend, "delete_resource_policy"):
            setattr(
                SecretsManagerBackend,
                "delete_resource_policy",
                delete_resource_policy_model,
            )

        def delete_resource_policy_response(self):
            secret_id = self._get_param("SecretId")
            return secretsmanager_backends[self.region].delete_resource_policy(secret_id=secret_id)

        if not hasattr(SecretsManagerResponse, "delete_resource_policy"):
            setattr(
                SecretsManagerResponse,
                "delete_resource_policy",
                delete_resource_policy_response,
            )

        def put_resource_policy_model(self, secret_id, resource_policy):
            policy_validator = IAMPolicyDocumentValidator(resource_policy)
            policy_validator._validate_top_elements()
            policy_validator._validate_version_syntax()
            if self._is_valid_identifier(secret_id):
                self.secrets[secret_id].policy = resource_policy
                return json.dumps(
                    {
                        "ARN": self.secrets[secret_id].arn,
                        "Name": self.secrets[secret_id].secret_id,
                    }
                )
            else:
                raise SecretNotFoundException()

        if not hasattr(SecretsManagerBackend, "put_resource_policy"):
            setattr(SecretsManagerBackend, "put_resource_policy", put_resource_policy_model)

        def put_resource_policy_response(self):
            secret_id = self._get_param("SecretId")
            resource_policy = self._get_param("ResourcePolicy")
            return secretsmanager_backends[self.region].put_resource_policy(
                secret_id=secret_id, resource_policy=json.loads(resource_policy)
            )

        if not hasattr(SecretsManagerResponse, "put_resource_policy"):
            setattr(SecretsManagerResponse, "put_resource_policy", put_resource_policy_response)

    def cancel_rotate_secret(
        self, context: RequestContext, secret_id: SecretIdType
    ) -> CancelRotateSecretResponse:
        raise NotImplementedError

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
        res = call_moto(context)
        return CreateSecretResponse(**res)

    def delete_resource_policy(
        self, context: RequestContext, secret_id: SecretIdType
    ) -> DeleteResourcePolicyResponse:
        res = call_moto(context)
        return DeleteResourcePolicyResponse(**res)

    def delete_secret(
        self,
        context: RequestContext,
        secret_id: SecretIdType,
        recovery_window_in_days: RecoveryWindowInDaysType = None,
        force_delete_without_recovery: BooleanType = None,
    ) -> DeleteSecretResponse:
        res = call_moto(context)
        return DeleteSecretResponse(**res)

    def describe_secret(
        self, context: RequestContext, secret_id: SecretIdType
    ) -> DescribeSecretResponse:
        res = call_moto(context)
        return DescribeSecretResponse(**res)

    def get_random_password(
        self,
        context: RequestContext,
        password_length: PasswordLengthType = None,
        exclude_characters: ExcludeCharactersType = None,
        exclude_numbers: ExcludeNumbersType = None,
        exclude_punctuation: ExcludePunctuationType = None,
        exclude_uppercase: ExcludeUppercaseType = None,
        exclude_lowercase: ExcludeLowercaseType = None,
        include_space: IncludeSpaceType = None,
        require_each_included_type: RequireEachIncludedTypeType = None,
    ) -> GetRandomPasswordResponse:
        res = call_moto(context)
        return GetRandomPasswordResponse(**res)

    def get_resource_policy(
        self, context: RequestContext, secret_id: SecretIdType
    ) -> GetResourcePolicyResponse:
        res = call_moto(context)
        return GetResourcePolicyResponse(**res)

    def get_secret_value(
        self,
        context: RequestContext,
        secret_id: SecretIdType,
        version_id: SecretVersionIdType = None,
        version_stage: SecretVersionStageType = None,
    ) -> GetSecretValueResponse:
        res = call_moto(context)
        return GetSecretValueResponse(**res)

    def list_secret_version_ids(
        self,
        context: RequestContext,
        secret_id: SecretIdType,
        max_results: MaxResultsType = None,
        next_token: NextTokenType = None,
        include_deprecated: BooleanType = None,
    ) -> ListSecretVersionIdsResponse:
        res = call_moto(context)
        return ListSecretVersionIdsResponse(**res)

    def list_secrets(
        self,
        context: RequestContext,
        max_results: MaxResultsType = None,
        next_token: NextTokenType = None,
        filters: FiltersListType = None,
        sort_order: SortOrderType = None,
    ) -> ListSecretsResponse:
        res = call_moto(context)
        return ListSecretsResponse(**res)

    def put_resource_policy(
        self,
        context: RequestContext,
        secret_id: SecretIdType,
        resource_policy: NonEmptyResourcePolicyType,
        block_public_policy: BooleanType = None,
    ) -> PutResourcePolicyResponse:
        res = call_moto(context)
        return PutResourcePolicyResponse(**res)

    def put_secret_value(
        self,
        context: RequestContext,
        secret_id: SecretIdType,
        client_request_token: ClientRequestTokenType = None,
        secret_binary: SecretBinaryType = None,
        secret_string: SecretStringType = None,
        version_stages: SecretVersionStagesType = None,
    ) -> PutSecretValueResponse:
        res = call_moto(context)
        return PutSecretValueResponse(**res)

    def remove_regions_from_replication(
        self,
        context: RequestContext,
        secret_id: SecretIdType,
        remove_replica_regions: RemoveReplicaRegionListType,
    ) -> RemoveRegionsFromReplicationResponse:
        res = call_moto(context)
        return RemoveRegionsFromReplicationResponse(**res)

    def replicate_secret_to_regions(
        self,
        context: RequestContext,
        secret_id: SecretIdType,
        add_replica_regions: AddReplicaRegionListType,
        force_overwrite_replica_secret: BooleanType = None,
    ) -> ReplicateSecretToRegionsResponse:
        res = call_moto(context)
        return ReplicateSecretToRegionsResponse(**res)

    def restore_secret(
        self, context: RequestContext, secret_id: SecretIdType
    ) -> RestoreSecretResponse:
        res = call_moto(context)
        return RestoreSecretResponse(**res)

    def rotate_secret(
        self,
        context: RequestContext,
        secret_id: SecretIdType,
        client_request_token: ClientRequestTokenType = None,
        rotation_lambda_arn: RotationLambdaARNType = None,
        rotation_rules: RotationRulesType = None,
        rotate_immediately: BooleanType = None,
    ) -> RotateSecretResponse:
        res = call_moto(context)
        return RotateSecretResponse(**res)

    def stop_replication_to_replica(
        self, context: RequestContext, secret_id: SecretIdType
    ) -> StopReplicationToReplicaResponse:
        res = call_moto(context)
        return StopReplicationToReplicaResponse(**res)

    def tag_resource(
        self, context: RequestContext, secret_id: SecretIdType, tags: TagListType
    ) -> None:
        call_moto(context)

    def untag_resource(
        self, context: RequestContext, secret_id: SecretIdType, tag_keys: TagKeyListType
    ) -> None:
        call_moto(context)

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
        res = call_moto(context)
        return UpdateSecretResponse(**res)

    def update_secret_version_stage(
        self,
        context: RequestContext,
        secret_id: SecretIdType,
        version_stage: SecretVersionStageType,
        remove_from_version_id: SecretVersionIdType = None,
        move_to_version_id: SecretVersionIdType = None,
    ) -> UpdateSecretVersionStageResponse:
        res = call_moto(context)
        return UpdateSecretVersionStageResponse(**res)

    def validate_resource_policy(
        self,
        context: RequestContext,
        resource_policy: NonEmptyResourcePolicyType,
        secret_id: SecretIdType = None,
    ) -> ValidateResourcePolicyResponse:
        res = call_moto(context)
        return ValidateResourcePolicyResponse(**res)
