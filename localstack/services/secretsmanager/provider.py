from __future__ import annotations

import json
import logging
import re
from typing import Dict, Optional

from moto.iam.policy_validation import IAMPolicyDocumentValidator
from moto.secretsmanager import models as secretsmanager_models
from moto.secretsmanager.exceptions import SecretNotFoundException, ValidationException
from moto.secretsmanager.models import FakeSecret, SecretsManagerBackend, secretsmanager_backends
from moto.secretsmanager.responses import SecretsManagerResponse

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
from localstack.constants import TEST_AWS_ACCOUNT_ID
from localstack.services.moto import call_moto, call_moto_with_request
from localstack.utils.aws import aws_stack
from localstack.utils.common import to_str
from localstack.utils.patch import patch
from localstack.utils.strings import short_uid
from localstack.utils.time import today_no_time

LOG = logging.getLogger(__name__)

# maps key names to ARNs
SECRET_ARN_STORAGE = {}


class SecretsmanagerProvider(SecretsmanagerApi):
    def __init__(self):
        super().__init__()
        apply_patches()

    @staticmethod
    def _transform_context_secret_id(context: RequestContext) -> Optional[Dict]:
        # If secret ARN ends with "-<randomId>" this is removed from the request for upstream compatibility.
        data = json.loads(to_str(context.request.data or "{}"))
        secret_id = data.get("SecretId", None)
        if secret_id and re.match(r"^arn:", secret_id):
            arn = aws_stack.parse_arn(secret_id)
            aws_region = aws_stack.get_region()
            if arn["region"] != aws_region:
                LOG.info(f'Expected request region "{aws_region}" for secret "{secret_id}"')
            resource_id = arn["resource"].split(":")[-1]
            if resource_id[-7] == "-":
                data["SecretId"] = resource_id[:-7]
            elif resource_id[-1] != "-":
                data["SecretId"] += "-"
            return data
        return None

    @staticmethod
    def _validate_secret_id(secret_id: SecretIdType) -> bool:
        # The secret name can contain ASCII letters, numbers, and the following characters: /_+=.@-
        return bool(re.match(r"^[A-Za-z0-9/_+=.@-]+\Z", secret_id))

    @staticmethod
    def _raise_if_invalid_secret_id(secret_id: SecretIdType):
        # Patches moto's implementation for which secret_ids are not validated, by raising a ValidationException.
        # Skips this check if the secret_id provided appears to be an arn (starting with 'arn:').
        if not re.match(
            r"^arn:", secret_id
        ):  # Check if it appears to be an arn: so to skip secret_id check: delegate parsing of arn to handlers.
            if not SecretsmanagerProvider._validate_secret_id(secret_id):
                raise ValidationException(
                    "Invalid name. Must be a valid name containing alphanumeric "
                    "characters, or any of the following: -/_+=.@!"
                )

    @staticmethod
    def _call_moto_with_request_secret_id(context: RequestContext) -> ServiceResponse:
        data_dict = SecretsmanagerProvider._transform_context_secret_id(context)
        return call_moto_with_request(context, data_dict) if data_dict else call_moto(context)

    def cancel_rotate_secret(
        self, context: RequestContext, secret_id: SecretIdType
    ) -> CancelRotateSecretResponse:
        return self._call_moto_with_request_secret_id(context)

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
        self._raise_if_invalid_secret_id(name)
        return self._call_moto_with_request_secret_id(context)

    def delete_resource_policy(
        self, context: RequestContext, secret_id: SecretIdType
    ) -> DeleteResourcePolicyResponse:
        self._raise_if_invalid_secret_id(secret_id)
        return self._call_moto_with_request_secret_id(context)

    def delete_secret(
        self,
        context: RequestContext,
        secret_id: SecretIdType,
        recovery_window_in_days: RecoveryWindowInDaysType = None,
        force_delete_without_recovery: BooleanType = None,
    ) -> DeleteSecretResponse:
        self._raise_if_invalid_secret_id(secret_id)
        return self._call_moto_with_request_secret_id(context)

    def describe_secret(
        self, context: RequestContext, secret_id: SecretIdType
    ) -> DescribeSecretResponse:
        self._raise_if_invalid_secret_id(secret_id)
        return self._call_moto_with_request_secret_id(context)

    def get_resource_policy(
        self, context: RequestContext, secret_id: SecretIdType
    ) -> GetResourcePolicyResponse:
        self._raise_if_invalid_secret_id(secret_id)
        return self._call_moto_with_request_secret_id(context)

    def get_secret_value(
        self,
        context: RequestContext,
        secret_id: SecretIdType,
        version_id: SecretVersionIdType = None,
        version_stage: SecretVersionStageType = None,
    ) -> GetSecretValueResponse:
        self._raise_if_invalid_secret_id(secret_id)
        return self._call_moto_with_request_secret_id(context)

    def list_secret_version_ids(
        self,
        context: RequestContext,
        secret_id: SecretIdType,
        max_results: MaxResultsType = None,
        next_token: NextTokenType = None,
        include_deprecated: BooleanType = None,
    ) -> ListSecretVersionIdsResponse:
        self._raise_if_invalid_secret_id(secret_id)
        return self._call_moto_with_request_secret_id(context)

    def put_resource_policy(
        self,
        context: RequestContext,
        secret_id: SecretIdType,
        resource_policy: NonEmptyResourcePolicyType,
        block_public_policy: BooleanType = None,
    ) -> PutResourcePolicyResponse:
        self._raise_if_invalid_secret_id(secret_id)
        return self._call_moto_with_request_secret_id(context)

    def put_secret_value(
        self,
        context: RequestContext,
        secret_id: SecretIdType,
        client_request_token: ClientRequestTokenType = None,
        secret_binary: SecretBinaryType = None,
        secret_string: SecretStringType = None,
        version_stages: SecretVersionStagesType = None,
    ) -> PutSecretValueResponse:
        self._raise_if_invalid_secret_id(secret_id)
        return self._call_moto_with_request_secret_id(context)

    def remove_regions_from_replication(
        self,
        context: RequestContext,
        secret_id: SecretIdType,
        remove_replica_regions: RemoveReplicaRegionListType,
    ) -> RemoveRegionsFromReplicationResponse:
        self._raise_if_invalid_secret_id(secret_id)
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
        self._raise_if_invalid_secret_id(secret_id)
        return self._call_moto_with_request_secret_id(context)

    def restore_secret(
        self, context: RequestContext, secret_id: SecretIdType
    ) -> RestoreSecretResponse:
        self._raise_if_invalid_secret_id(secret_id)
        return self._call_moto_with_request_secret_id(context)

    def rotate_secret(
        self,
        context: RequestContext,
        secret_id: SecretIdType,
        client_request_token: ClientRequestTokenType = None,
        rotation_lambda_arn: RotationLambdaARNType = None,
        rotation_rules: RotationRulesType = None,
        rotate_immediately: BooleanType = None,
    ) -> RotateSecretResponse:
        self._raise_if_invalid_secret_id(secret_id)
        return self._call_moto_with_request_secret_id(context)

    def stop_replication_to_replica(
        self, context: RequestContext, secret_id: SecretIdType
    ) -> StopReplicationToReplicaResponse:
        self._raise_if_invalid_secret_id(secret_id)
        return self._call_moto_with_request_secret_id(context)

    def tag_resource(
        self, context: RequestContext, secret_id: SecretIdType, tags: TagListType
    ) -> None:
        self._raise_if_invalid_secret_id(secret_id)
        self._call_moto_with_request_secret_id(context)

    def untag_resource(
        self, context: RequestContext, secret_id: SecretIdType, tag_keys: TagKeyListType
    ) -> None:
        self._raise_if_invalid_secret_id(secret_id)
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
        self._raise_if_invalid_secret_id(secret_id)
        return self._call_moto_with_request_secret_id(context)

    def update_secret_version_stage(
        self,
        context: RequestContext,
        secret_id: SecretIdType,
        version_stage: SecretVersionStageType,
        remove_from_version_id: SecretVersionIdType = None,
        move_to_version_id: SecretVersionIdType = None,
    ) -> UpdateSecretVersionStageResponse:
        self._raise_if_invalid_secret_id(secret_id)
        return self._call_moto_with_request_secret_id(context)

    def validate_resource_policy(
        self,
        context: RequestContext,
        resource_policy: NonEmptyResourcePolicyType,
        secret_id: SecretIdType = None,
    ) -> ValidateResourcePolicyResponse:
        self._raise_if_invalid_secret_id(secret_id)
        return self._call_moto_with_request_secret_id(context)


@patch(FakeSecret.__init__)
def fake_secret__init__(fn, self, **kwargs):
    fn(self, **kwargs)

    # The last date that the secret value was retrieved.
    # This value does not include the time.
    # This field is omitted if the secret has never been retrieved.
    # Type: Timestamp
    self.last_accessed_date = None


@patch(SecretsManagerBackend.get_secret_value)
def moto_smb_get_secret_value(fn, self, secret_id, version_id, version_stage):
    res = fn(self, secret_id, version_id, version_stage)

    secret_id = self.secrets[secret_id]
    if secret_id:  # Redundant, we know from the response it exists: no exceptions.
        secret_id.last_accessed_date = today_no_time()
    else:
        LOG.warning(
            f'Expected Secret to exist on non failing GetSecretValue request for SecretId "{secret_id}"'
        )

    return res


@patch(FakeSecret.to_dict)
def fake_secret_to_dict(fn, self):
    res_dict = fn(self)
    if self.last_accessed_date:
        res_dict["LastAccessedDate"] = self.last_accessed_date
    return res_dict


def secretsmanager_models_secret_arn(region, secret_id):
    k = f"{region}_{secret_id}"
    if k not in SECRET_ARN_STORAGE:
        id_string = short_uid()[:6]
        arn = aws_stack.secretsmanager_secret_arn(
            secret_id, account_id=TEST_AWS_ACCOUNT_ID, region_name=region, random_suffix=id_string
        )
        SECRET_ARN_STORAGE[k] = arn
    return SECRET_ARN_STORAGE[k]


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


def get_resource_policy_response(self):
    secret_id = self._get_param("SecretId")
    return secretsmanager_backends[self.region].get_resource_policy(secret_id=secret_id)


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


def delete_resource_policy_response(self):
    secret_id = self._get_param("SecretId")
    return secretsmanager_backends[self.region].delete_resource_policy(secret_id=secret_id)


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


def put_resource_policy_response(self):
    secret_id = self._get_param("SecretId")
    resource_policy = self._get_param("ResourcePolicy")
    return secretsmanager_backends[self.region].put_resource_policy(
        secret_id=secret_id, resource_policy=json.loads(resource_policy)
    )


def apply_patches():
    secretsmanager_models.secret_arn = secretsmanager_models_secret_arn
    setattr(SecretsManagerBackend, "get_resource_policy", get_resource_policy_model)
    setattr(SecretsManagerResponse, "get_resource_policy", get_resource_policy_response)
    if not hasattr(SecretsManagerBackend, "delete_resource_policy"):
        setattr(
            SecretsManagerBackend,
            "delete_resource_policy",
            delete_resource_policy_model,
        )
    if not hasattr(SecretsManagerResponse, "delete_resource_policy"):
        setattr(
            SecretsManagerResponse,
            "delete_resource_policy",
            delete_resource_policy_response,
        )
    if not hasattr(SecretsManagerBackend, "put_resource_policy"):
        setattr(SecretsManagerBackend, "put_resource_policy", put_resource_policy_model)
    if not hasattr(SecretsManagerResponse, "put_resource_policy"):
        setattr(SecretsManagerResponse, "put_resource_policy", put_resource_policy_response)
