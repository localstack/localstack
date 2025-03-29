from __future__ import annotations

import base64
import json
import logging
import re
import time
from typing import Any, Final, Optional, Union

import moto.secretsmanager.exceptions as moto_exception
from botocore.utils import InvalidArnException
from moto.iam.policy_validation import IAMPolicyDocumentValidator
from moto.secretsmanager import secretsmanager_backends
from moto.secretsmanager.models import FakeSecret, SecretsManagerBackend
from moto.secretsmanager.responses import SecretsManagerResponse

from localstack.aws.api import CommonServiceException, RequestContext, handler
from localstack.aws.api.secretsmanager import (
    CancelRotateSecretRequest,
    CancelRotateSecretResponse,
    CreateSecretRequest,
    CreateSecretResponse,
    DeleteResourcePolicyRequest,
    DeleteResourcePolicyResponse,
    DeleteSecretRequest,
    DeleteSecretResponse,
    DescribeSecretRequest,
    DescribeSecretResponse,
    GetResourcePolicyRequest,
    GetResourcePolicyResponse,
    GetSecretValueRequest,
    GetSecretValueResponse,
    InvalidParameterException,
    InvalidRequestException,
    ListSecretVersionIdsRequest,
    ListSecretVersionIdsResponse,
    NameType,
    PutResourcePolicyRequest,
    PutResourcePolicyResponse,
    PutSecretValueRequest,
    PutSecretValueResponse,
    RemoveRegionsFromReplicationRequest,
    RemoveRegionsFromReplicationResponse,
    ReplicateSecretToRegionsRequest,
    ReplicateSecretToRegionsResponse,
    ResourceExistsException,
    ResourceNotFoundException,
    RestoreSecretRequest,
    RestoreSecretResponse,
    RotateSecretRequest,
    RotateSecretResponse,
    SecretIdType,
    SecretsmanagerApi,
    SecretVersionsListEntry,
    StopReplicationToReplicaRequest,
    StopReplicationToReplicaResponse,
    TagResourceRequest,
    UntagResourceRequest,
    UpdateSecretRequest,
    UpdateSecretResponse,
    UpdateSecretVersionStageRequest,
    UpdateSecretVersionStageResponse,
    ValidateResourcePolicyRequest,
    ValidateResourcePolicyResponse,
)
from localstack.aws.connect import connect_to
from localstack.services.moto import call_moto
from localstack.utils.aws import arns
from localstack.utils.patch import patch
from localstack.utils.time import today_no_time

# Constants.
AWSPREVIOUS: Final[str] = "AWSPREVIOUS"
AWSPENDING: Final[str] = "AWSPENDING"
AWSCURRENT: Final[str] = "AWSCURRENT"
# The maximum number of outdated versions that can be stored in the secret.
# see: https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_PutSecretValue.html
MAX_OUTDATED_SECRET_VERSIONS: Final[int] = 100
#
# Error Messages.
AWS_INVALID_REQUEST_MESSAGE_CREATE_WITH_SCHEDULED_DELETION: Final[str] = (
    "You can't create this secret because a secret with this name is already scheduled for deletion."
)

LOG = logging.getLogger(__name__)


class ValidationException(CommonServiceException):
    def __init__(self, message: str):
        super().__init__("ValidationException", message, 400, True)


class SecretNotFoundException(CommonServiceException):
    def __init__(self):
        super().__init__(
            "ResourceNotFoundException",
            "Secrets Manager can't find the specified secret.",
            400,
            True,
        )


class SecretsmanagerProvider(SecretsmanagerApi):
    def __init__(self):
        super().__init__()
        apply_patches()

    @staticmethod
    def get_moto_backend_for_resource(
        name_or_arn: str, context: RequestContext
    ) -> SecretsManagerBackend:
        try:
            arn_data = arns.parse_arn(name_or_arn)
            backend = secretsmanager_backends[arn_data["account"]][arn_data["region"]]
        except InvalidArnException:
            backend = secretsmanager_backends[context.account_id][context.region]
        return backend

    @staticmethod
    def _raise_if_default_kms_key(
        secret_id: str, request: RequestContext, backend: SecretsManagerBackend
    ):
        try:
            secret = backend.describe_secret(secret_id)
        except moto_exception.SecretNotFoundException:
            raise ResourceNotFoundException("Secrets Manager can't find the specified secret.")
        if secret.kms_key_id is None and request.account_id != secret.account_id:
            raise InvalidRequestException(
                "You can't access a secret from a different AWS account if you encrypt the secret with the default KMS service key."
            )

    @staticmethod
    def _validate_secret_id(secret_id: SecretIdType) -> bool:
        # The secret name can contain ASCII letters, numbers, and the following characters: /_+=.@-
        return bool(re.match(r"^[A-Za-z0-9/_+=.@-]+\Z", secret_id))

    @staticmethod
    def _raise_if_invalid_secret_id(secret_id: Union[SecretIdType, NameType]):
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
    def _raise_if_missing_client_req_token(
        request: Union[
            CreateSecretRequest,
            PutSecretValueRequest,
            RotateSecretRequest,
            UpdateSecretRequest,
        ],
    ):
        if "ClientRequestToken" not in request:
            raise InvalidRequestException(
                "You must provide a ClientRequestToken value. We recommend a UUID-type value."
            )

    @handler("CancelRotateSecret", expand=False)
    def cancel_rotate_secret(
        self, context: RequestContext, request: CancelRotateSecretRequest
    ) -> CancelRotateSecretResponse:
        self._raise_if_invalid_secret_id(request["SecretId"])
        return call_moto(context, request)

    @handler("CreateSecret", expand=False)
    def create_secret(
        self, context: RequestContext, request: CreateSecretRequest
    ) -> CreateSecretResponse:
        self._raise_if_missing_client_req_token(request)
        # Some providers need to create keys which are not usually creatable by users
        if not any(
            tag_entry["Key"] == "BYPASS_SECRET_ID_VALIDATION"
            for tag_entry in request.get("Tags", [])
        ):
            self._raise_if_invalid_secret_id(request["Name"])
        else:
            request["Tags"] = [
                tag_entry
                for tag_entry in request.get("Tags", [])
                if tag_entry["Key"] != "BYPASS_SECRET_ID_VALIDATION"
            ]

        return call_moto(context, request)

    @handler("DeleteResourcePolicy", expand=False)
    def delete_resource_policy(
        self, context: RequestContext, request: DeleteResourcePolicyRequest
    ) -> DeleteResourcePolicyResponse:
        self._raise_if_invalid_secret_id(request["SecretId"])
        return call_moto(context, request)

    @handler("DeleteSecret", expand=False)
    def delete_secret(
        self, context: RequestContext, request: DeleteSecretRequest
    ) -> DeleteSecretResponse:
        secret_id: str = request["SecretId"]
        self._raise_if_invalid_secret_id(secret_id)
        recovery_window_in_days: Optional[int] = request.get("RecoveryWindowInDays")
        force_delete_without_recovery: Optional[bool] = request.get("ForceDeleteWithoutRecovery")

        backend = SecretsmanagerProvider.get_moto_backend_for_resource(secret_id, context)
        try:
            arn, name, deletion_date = backend.delete_secret(
                secret_id=secret_id,
                recovery_window_in_days=recovery_window_in_days,
                force_delete_without_recovery=force_delete_without_recovery,
            )
        except moto_exception.InvalidParameterException as e:
            raise InvalidParameterException(str(e))
        except moto_exception.InvalidRequestException:
            raise InvalidRequestException(
                "You tried to perform the operation on a secret that's currently marked deleted."
            )
        except moto_exception.SecretNotFoundException:
            raise SecretNotFoundException()
        return DeleteSecretResponse(ARN=arn, Name=name, DeletionDate=deletion_date)

    @handler("DescribeSecret", expand=False)
    def describe_secret(
        self, context: RequestContext, request: DescribeSecretRequest
    ) -> DescribeSecretResponse:
        secret_id: str = request["SecretId"]
        self._raise_if_invalid_secret_id(secret_id)
        backend = SecretsmanagerProvider.get_moto_backend_for_resource(secret_id, context)
        try:
            secret = backend.describe_secret(secret_id)
        except moto_exception.SecretNotFoundException:
            raise ResourceNotFoundException("Secrets Manager can't find the specified secret.")
        return DescribeSecretResponse(**secret.to_dict())

    @handler("GetResourcePolicy", expand=False)
    def get_resource_policy(
        self, context: RequestContext, request: GetResourcePolicyRequest
    ) -> GetResourcePolicyResponse:
        secret_id = request["SecretId"]
        self._raise_if_invalid_secret_id(secret_id)
        backend = SecretsmanagerProvider.get_moto_backend_for_resource(secret_id, context)
        policy = backend.get_resource_policy(secret_id)
        return GetResourcePolicyResponse(**json.loads(policy))

    @handler("GetSecretValue", expand=False)
    def get_secret_value(
        self, context: RequestContext, request: GetSecretValueRequest
    ) -> GetSecretValueResponse:
        secret_id = request.get("SecretId")
        version_id = request.get("VersionId")
        version_stage = request.get("VersionStage")
        if not version_id and not version_stage:
            version_stage = "AWSCURRENT"
        self._raise_if_invalid_secret_id(secret_id)
        backend = SecretsmanagerProvider.get_moto_backend_for_resource(secret_id, context)
        self._raise_if_default_kms_key(secret_id, context, backend)
        try:
            response = backend.get_secret_value(secret_id, version_id, version_stage)
            response = decode_secret_binary_from_response(response)
        except moto_exception.SecretNotFoundException:
            raise ResourceNotFoundException(
                f"Secrets Manager can't find the specified secret value for staging label: {version_stage}"
            )
        except moto_exception.ResourceNotFoundException:
            error_message = (
                f"VersionId: {version_id}" if version_id else f"staging label: {version_stage}"
            )
            raise ResourceNotFoundException(
                f"Secrets Manager can't find the specified secret value for {error_message}"
            )
        except moto_exception.SecretStageVersionMismatchException:
            raise InvalidRequestException(
                "You provided a VersionStage that is not associated to the provided VersionId."
            )
        except moto_exception.SecretHasNoValueException:
            raise ResourceNotFoundException(
                f"Secrets Manager can't find the specified secret value for staging label: {version_stage}"
            )
        except moto_exception.InvalidRequestException:
            raise InvalidRequestException(
                "You can't perform this operation on the secret because it was marked for deletion."
            )
        return GetSecretValueResponse(**response)

    @handler("ListSecretVersionIds", expand=False)
    def list_secret_version_ids(
        self, context: RequestContext, request: ListSecretVersionIdsRequest
    ) -> ListSecretVersionIdsResponse:
        secret_id = request["SecretId"]
        include_deprecated = request.get("IncludeDeprecated", False)
        self._raise_if_invalid_secret_id(secret_id)
        backend = SecretsmanagerProvider.get_moto_backend_for_resource(secret_id, context)
        secrets = backend.list_secret_version_ids(secret_id, include_deprecated=include_deprecated)
        return ListSecretVersionIdsResponse(**json.loads(secrets))

    @handler("PutResourcePolicy", expand=False)
    def put_resource_policy(
        self, context: RequestContext, request: PutResourcePolicyRequest
    ) -> PutResourcePolicyResponse:
        secret_id = request["SecretId"]
        self._raise_if_invalid_secret_id(secret_id)
        backend = SecretsmanagerProvider.get_moto_backend_for_resource(secret_id, context)
        arn, name = backend.put_resource_policy(secret_id, request["ResourcePolicy"])
        return PutResourcePolicyResponse(ARN=arn, Name=name)

    @handler("PutSecretValue", expand=False)
    def put_secret_value(
        self, context: RequestContext, request: PutSecretValueRequest
    ) -> PutSecretValueResponse:
        secret_id = request["SecretId"]
        self._raise_if_invalid_secret_id(secret_id)
        self._raise_if_missing_client_req_token(request)
        client_req_token = request.get("ClientRequestToken")
        secret_string = request.get("SecretString")
        secret_binary = request.get("SecretBinary")
        if not secret_binary and not secret_string:
            raise InvalidRequestException("You must provide either SecretString or SecretBinary.")

        version_stages = request.get("VersionStages", ["AWSCURRENT"])
        if not isinstance(version_stages, list):
            version_stages = [version_stages]

        backend = SecretsmanagerProvider.get_moto_backend_for_resource(secret_id, context)
        self._raise_if_default_kms_key(secret_id, context, backend)

        response = backend.put_secret_value(
            secret_id=secret_id,
            secret_binary=secret_binary,
            secret_string=secret_string,
            version_stages=version_stages,
            client_request_token=client_req_token,
        )
        return PutSecretValueResponse(**json.loads(response))

    @handler("RemoveRegionsFromReplication", expand=False)
    def remove_regions_from_replication(
        self, context: RequestContext, request: RemoveRegionsFromReplicationRequest
    ) -> RemoveRegionsFromReplicationResponse:
        self._raise_if_invalid_secret_id(request["SecretId"])
        return call_moto(context, request)

    @handler("ReplicateSecretToRegions", expand=False)
    def replicate_secret_to_regions(
        self, context: RequestContext, request: ReplicateSecretToRegionsRequest
    ) -> ReplicateSecretToRegionsResponse:
        self._raise_if_invalid_secret_id(request["SecretId"])
        return call_moto(context, request)

    @handler("RestoreSecret", expand=False)
    def restore_secret(
        self, context: RequestContext, request: RestoreSecretRequest
    ) -> RestoreSecretResponse:
        secret_id = request["SecretId"]
        self._raise_if_invalid_secret_id(secret_id)
        backend = SecretsmanagerProvider.get_moto_backend_for_resource(secret_id, context)
        try:
            arn, name = backend.restore_secret(secret_id)
        except moto_exception.SecretNotFoundException:
            raise ResourceNotFoundException("Secrets Manager can't find the specified secret.")
        return RestoreSecretResponse(ARN=arn, Name=name)

    @handler("RotateSecret", expand=False)
    def rotate_secret(
        self, context: RequestContext, request: RotateSecretRequest
    ) -> RotateSecretResponse:
        self._raise_if_missing_client_req_token(request)
        self._raise_if_invalid_secret_id(request["SecretId"])
        return call_moto(context, request)

    @handler("StopReplicationToReplica", expand=False)
    def stop_replication_to_replica(
        self, context: RequestContext, request: StopReplicationToReplicaRequest
    ) -> StopReplicationToReplicaResponse:
        self._raise_if_invalid_secret_id(request["SecretId"])
        return call_moto(context, request)

    @handler("TagResource", expand=False)
    def tag_resource(self, context: RequestContext, request: TagResourceRequest) -> None:
        secret_id = request["SecretId"]
        tags = request["Tags"]
        self._raise_if_invalid_secret_id(secret_id)
        backend = SecretsmanagerProvider.get_moto_backend_for_resource(secret_id, context)
        backend.tag_resource(secret_id, tags)

    @handler("UntagResource", expand=False)
    def untag_resource(self, context: RequestContext, request: UntagResourceRequest) -> None:
        secret_id = request["SecretId"]
        tag_keys = request.get("TagKeys")
        self._raise_if_invalid_secret_id(secret_id)
        backend = SecretsmanagerProvider.get_moto_backend_for_resource(secret_id, context)
        backend.untag_resource(secret_id=secret_id, tag_keys=tag_keys)

    @handler("UpdateSecret", expand=False)
    def update_secret(
        self, context: RequestContext, request: UpdateSecretRequest
    ) -> UpdateSecretResponse:
        # if we're modifying the value of the secret, ClientRequestToken is required
        secret_id = request["SecretId"]
        secret_string = request.get("SecretString")
        secret_binary = request.get("SecretBinary")
        description = request.get("Description")
        kms_key_id = request.get("KmsKeyId")
        client_req_token = request.get("ClientRequestToken")
        self._raise_if_invalid_secret_id(secret_id)
        self._raise_if_missing_client_req_token(request)

        backend = SecretsmanagerProvider.get_moto_backend_for_resource(secret_id, context)
        try:
            secret = backend.update_secret(
                secret_id,
                description=description,
                secret_string=secret_string,
                secret_binary=secret_binary,
                client_request_token=client_req_token,
                kms_key_id=kms_key_id,
            )
        except moto_exception.SecretNotFoundException:
            raise ResourceNotFoundException("Secrets Manager can't find the specified secret.")
        except moto_exception.OperationNotPermittedOnReplica:
            raise InvalidRequestException(
                "Operation not permitted on a replica secret. Call must be made in primary secret's region."
            )
        except moto_exception.InvalidRequestException:
            raise InvalidRequestException(
                "An error occurred (InvalidRequestException) when calling the UpdateSecret operation: "
                "You can't perform this operation on the secret because it was marked for deletion."
            )
        return UpdateSecretResponse(**json.loads(secret))

    @handler("UpdateSecretVersionStage", expand=False)
    def update_secret_version_stage(
        self, context: RequestContext, request: UpdateSecretVersionStageRequest
    ) -> UpdateSecretVersionStageResponse:
        self._raise_if_invalid_secret_id(request["SecretId"])
        return call_moto(context, request)

    @handler("ValidateResourcePolicy", expand=False)
    def validate_resource_policy(
        self, context: RequestContext, request: ValidateResourcePolicyRequest
    ) -> ValidateResourcePolicyResponse:
        self._raise_if_invalid_secret_id(request["SecretId"])
        return call_moto(context, request)


@patch(FakeSecret.__init__)
def fake_secret__init__(fn, self, *args, **kwargs):
    fn(self, *args, **kwargs)

    # Fix time not including millis.
    time_now = time.time()
    if kwargs.get("last_changed_date", None):
        self.last_changed_date = time_now
    if kwargs.get("created_date", None):
        self.created_date = time_now

    # The last date that the secret value was retrieved.
    # This value does not include the time.
    # This field is omitted if the secret has never been retrieved.
    self.last_accessed_date = None
    # Results in RotationEnabled being returned only if rotation was ever overwritten,
    # in which case this field is non-null, but an integer.
    self.auto_rotate_after_days = None
    self.rotation_lambda_arn = None


@patch(FakeSecret.update)
def fake_secret_update(
    fn, self, description=None, tags=None, kms_key_id=None, last_changed_date=None
):
    fn(self, description, tags, kms_key_id, last_changed_date)
    if last_changed_date is not None:
        self.last_changed_date = round(time.time(), 3)


@patch(SecretsManagerBackend.get_secret_value)
def moto_smb_get_secret_value(fn, self, secret_id, version_id, version_stage):
    res = fn(self, secret_id, version_id, version_stage)

    secret = self.secrets[secret_id]

    # Patch: update last accessed date on get.
    secret.last_accessed_date = today_no_time()

    # Patch: update version's last accessed date.
    secret_version = secret.versions.get(version_id or secret.default_version_id)
    if secret_version:
        secret_version["last_accessed_date"] = secret.last_accessed_date

    return res


@patch(SecretsManagerBackend.create_secret)
def moto_smb_create_secret(fn, self, name, *args, **kwargs):
    # Creating a secret with a SecretId equal to one that is scheduled for
    # deletion should raise an 'InvalidRequestException'.
    secret: Optional[FakeSecret] = self.secrets.get(name)
    if secret is not None and secret.deleted_date is not None:
        raise InvalidRequestException(AWS_INVALID_REQUEST_MESSAGE_CREATE_WITH_SCHEDULED_DELETION)

    if name in self.secrets:
        raise ResourceExistsException(
            f"The operation failed because the secret {name} already exists."
        )

    return fn(self, name, *args, **kwargs)


@patch(SecretsManagerBackend.list_secret_version_ids)
def moto_smb_list_secret_version_ids(
    _, self, secret_id: str, include_deprecated: bool, *args, **kwargs
):
    if secret_id not in self.secrets:
        raise SecretNotFoundException()

    if self.secrets[secret_id].is_deleted():
        raise InvalidRequestException(
            "An error occurred (InvalidRequestException) when calling the UpdateSecret operation: "
            "You can't perform this operation on the secret because it was marked for deletion."
        )

    secret = self.secrets[secret_id]

    # Patch: output format, report exact createdate instead of current time.
    versions: list[SecretVersionsListEntry] = list()
    for version_id, version in secret.versions.items():
        version_stages = version["version_stages"]
        # Patch: include deprecated versions if include_deprecated is True.
        # version_stages is empty if the version is deprecated.
        # see: https://docs.aws.amazon.com/secretsmanager/latest/userguide/getting-started.html#term_version
        if len(version_stages) > 0 or include_deprecated:
            entry = SecretVersionsListEntry(
                CreatedDate=version["createdate"],
                VersionId=version_id,
            )

            if version_stages:
                entry["VersionStages"] = version_stages

            # Patch: bind LastAccessedDate if one exists for this version.
            last_accessed_date = version.get("last_accessed_date")
            if last_accessed_date:
                entry["LastAccessedDate"] = last_accessed_date

            versions.append(entry)

    # Patch: sort versions by date.
    versions.sort(key=lambda v: v["CreatedDate"], reverse=True)

    response = ListSecretVersionIdsResponse(ARN=secret.arn, Name=secret.name, Versions=versions)

    return json.dumps(response)


@patch(FakeSecret.to_dict)
def fake_secret_to_dict(fn, self):
    res_dict = fn(self)
    if self.last_accessed_date:
        res_dict["LastAccessedDate"] = self.last_accessed_date
    if not self.description and "Description" in res_dict:
        del res_dict["Description"]
    if not self.rotation_enabled and "RotationEnabled" in res_dict:
        del res_dict["RotationEnabled"]
    if self.auto_rotate_after_days is None and "RotationRules" in res_dict:
        del res_dict["RotationRules"]
    if self.tags is None and "Tags" in res_dict:
        del res_dict["Tags"]
    for null_field in [key for key, value in res_dict.items() if value is None]:
        del res_dict[null_field]
    return res_dict


@patch(SecretsManagerBackend.update_secret)
def backend_update_secret(
    fn,
    self,
    secret_id,
    description=None,
    **kwargs,
):
    if secret_id not in self.secrets:
        raise SecretNotFoundException()

    if self.secrets[secret_id].is_deleted():
        raise InvalidRequestException(
            "An error occurred (InvalidRequestException) when calling the UpdateSecret operation: "
            "You can't perform this operation on the secret because it was marked for deletion."
        )

    secret = self.secrets[secret_id]
    version_id_t0 = secret.default_version_id

    requires_new_version: bool = any(
        [kwargs.get("kms_key_id"), kwargs.get("secret_binary"), kwargs.get("secret_string")]
    )
    if requires_new_version:
        fn(self, secret_id, **kwargs)

    if description is not None:
        secret.description = description

    version_id_t1 = secret.default_version_id

    resp: UpdateSecretResponse = UpdateSecretResponse()
    resp["ARN"] = secret.arn
    resp["Name"] = secret.name

    if version_id_t0 != version_id_t1:
        resp["VersionId"] = version_id_t1

    return json.dumps(resp)


@patch(SecretsManagerResponse.update_secret, pass_target=False)
def response_update_secret(self):
    secret_id = self._get_param("SecretId")
    description = self._get_param("Description")
    secret_string = self._get_param("SecretString")
    secret_binary = self._get_param("SecretBinary")
    client_request_token = self._get_param("ClientRequestToken")
    kms_key_id = self._get_param("KmsKeyId")
    return self.backend.update_secret(
        secret_id=secret_id,
        description=description,
        secret_string=secret_string,
        secret_binary=secret_binary,
        client_request_token=client_request_token,
        kms_key_id=kms_key_id,
    )


@patch(SecretsManagerBackend.update_secret_version_stage)
def backend_update_secret_version_stage(
    fn, self, secret_id, version_stage, remove_from_version_id, move_to_version_id
):
    fn(self, secret_id, version_stage, remove_from_version_id, move_to_version_id)

    secret = self.secrets[secret_id]

    # Patch: default version is the new AWSCURRENT version
    if version_stage == AWSCURRENT:
        secret.default_version_id = move_to_version_id

    versions_no_stages = []
    for version_id, version in secret.versions.items():
        version_stages = version["version_stages"]

        # moto appends a new AWSPREVIOUS label to the version AWSCURRENT was removed from,
        # but it does not remove the old AWSPREVIOUS label.
        # Patch: ensure only one AWSPREVIOUS tagged version is in the pool.
        if (
            version_stage == AWSCURRENT
            and version_id != remove_from_version_id
            and AWSPREVIOUS in version_stages
        ):
            version_stages.remove(AWSPREVIOUS)

        if not version_stages:
            versions_no_stages.append(version_id)

    # Patch: remove secret versions with no version stages.
    for version_no_stages in versions_no_stages:
        del secret.versions[version_no_stages]

    return secret.arn, secret.name


@patch(FakeSecret.reset_default_version)
def fake_secret_reset_default_version(fn, self, secret_version, version_id):
    fn(self, secret_version, version_id)

    # Remove versions with no version stages, if max limit of outdated versions is exceeded.
    versions_no_stages: list[str] = [
        version_id for version_id, version in self.versions.items() if not version["version_stages"]
    ]
    versions_to_delete: list[str] = []

    # Patch: remove outdated versions if the max deprecated versions limit is exceeded.
    if len(versions_no_stages) >= MAX_OUTDATED_SECRET_VERSIONS:
        versions_to_delete = versions_no_stages[
            : len(versions_no_stages) - MAX_OUTDATED_SECRET_VERSIONS
        ]

    for version_to_delete in versions_to_delete:
        del self.versions[version_to_delete]


@patch(FakeSecret.remove_version_stages_from_old_versions)
def fake_secret_remove_version_stages_from_old_versions(fn, self, version_stages):
    fn(self, version_stages)
    # Remove versions with no version stages.
    versions_no_stages = [
        version_id for version_id, version in self.versions.items() if not version["version_stages"]
    ]
    for version_no_stages in versions_no_stages:
        del self.versions[version_no_stages]


# Moto does not support rotate_immediately as an API parameter while the AWS API does
@patch(SecretsManagerResponse.rotate_secret, pass_target=False)
def rotate_secret(self) -> str:
    client_request_token = self._get_param("ClientRequestToken")
    rotation_lambda_arn = self._get_param("RotationLambdaARN")
    rotation_rules = self._get_param("RotationRules")
    rotate_immediately = self._get_param("RotateImmediately")
    secret_id = self._get_param("SecretId")
    return self.backend.rotate_secret(
        secret_id=secret_id,
        client_request_token=client_request_token,
        rotation_lambda_arn=rotation_lambda_arn,
        rotation_rules=rotation_rules,
        rotate_immediately=True if rotate_immediately is None else rotate_immediately,
    )


@patch(SecretsManagerBackend.rotate_secret)
def backend_rotate_secret(
    _,
    self,
    secret_id,
    client_request_token=None,
    rotation_lambda_arn=None,
    rotation_rules=None,
    rotate_immediately=True,
):
    rotation_days = "AutomaticallyAfterDays"

    if not self._is_valid_identifier(secret_id):
        raise SecretNotFoundException()

    secret = self.secrets[secret_id]
    if secret.is_deleted():
        raise InvalidRequestException(
            "An error occurred (InvalidRequestException) when calling the RotateSecret operation: You tried to \
            perform the operation on a secret that's currently marked deleted."
        )
    # Resolve rotation_lambda_arn and fallback to previous value if its missing
    # from the current request
    rotation_lambda_arn = rotation_lambda_arn or secret.rotation_lambda_arn
    if not rotation_lambda_arn:
        raise InvalidRequestException(
            "No Lambda rotation function ARN is associated with this secret."
        )

    if rotation_lambda_arn:
        if len(rotation_lambda_arn) > 2048:
            msg = "RotationLambdaARN must <= 2048 characters long."
            raise InvalidParameterException(msg)

    # In case rotation_period is not provided, resolve auto_rotate_after_days
    # and fallback to previous value if its missing from the current request.
    rotation_period = secret.auto_rotate_after_days or 0
    if rotation_rules:
        if rotation_days in rotation_rules:
            rotation_period = rotation_rules[rotation_days]
            if rotation_period < 1 or rotation_period > 1000:
                msg = "RotationRules.AutomaticallyAfterDays must be within 1-1000."
                raise InvalidParameterException(msg)

    try:
        lm_client = connect_to(region_name=self.region_name).lambda_
        lm_client.get_function(FunctionName=rotation_lambda_arn)
    except Exception:
        raise ResourceNotFoundException("Lambda does not exist or could not be accessed")

    # The rotation function must end with the versions of the secret in
    # one of two states:
    #
    #  - The AWSPENDING and AWSCURRENT staging labels are attached to the
    #    same version of the secret, or
    #  - The AWSPENDING staging label is not attached to any version of the secret.
    #
    # If the AWSPENDING staging label is present but not attached to the same
    # version as AWSCURRENT then any later invocation of RotateSecret assumes
    # that a previous rotation request is still in progress and returns an error.
    try:
        pending_version = None
        version = next(
            version
            for version in secret.versions.values()
            if AWSPENDING in version["version_stages"]
        )
        if AWSCURRENT not in version["version_stages"]:
            msg = "Previous rotation request is still in progress."
            # Delay exception, so we can trigger lambda again
            pending_version = [InvalidRequestException(msg), version]

    except StopIteration:
        # Pending is not present in any version
        pass

    secret.rotation_lambda_arn = rotation_lambda_arn
    secret.auto_rotate_after_days = rotation_period
    if secret.auto_rotate_after_days > 0:
        wait_interval_s = int(rotation_period) * 86400
        secret.next_rotation_date = int(time.time()) + wait_interval_s
        secret.rotation_enabled = True
        secret.rotation_requested = True

    if rotate_immediately:
        if not pending_version:
            # Begin the rotation process for the given secret by invoking the lambda function.
            #
            # We add the new secret version as "pending". The previous version remains
            # as "current" for now. Once we've passed the new secret through the lambda
            # rotation function (if provided) we can then update the status to "current".
            new_version_id = self._from_client_request_token(client_request_token)

            # An initial dummy secret value is necessary otherwise moto is not adding the new
            # secret version.
            self._add_secret(
                secret_id,
                "dummy_password",
                description=secret.description,
                tags=secret.tags,
                version_id=new_version_id,
                version_stages=[AWSPENDING],
            )

            # AWS secret rotation function templates have checks on existing values so we remove
            # the dummy value to force the lambda to generate a new one.
            del secret.versions[new_version_id]["secret_string"]
        else:
            new_version_id = pending_version.pop()["version_id"]

        try:
            for step in ["create", "set", "test", "finish"]:
                resp = lm_client.invoke(
                    FunctionName=rotation_lambda_arn,
                    Payload=json.dumps(
                        {
                            "Step": step + "Secret",
                            "SecretId": secret.name,
                            "ClientRequestToken": new_version_id,
                        }
                    ),
                )
                if resp.get("FunctionError"):
                    data = json.loads(resp.get("Payload").read())
                    raise Exception(data.get("errorType"))
        except Exception as e:
            LOG.debug("An exception (%s) has occurred in %s", str(e), rotation_lambda_arn)
            if pending_version:
                raise pending_version.pop()
            # Fall through if there is no previously pending version so we'll "stuck" with a new
            # secret version in AWSPENDING state.
    secret.last_rotation_date = int(time.time())
    return secret.to_short_dict(version_id=new_version_id)


@patch(moto_exception.SecretNotFoundException.__init__)
def moto_secret_not_found_exception_init(fn, self):
    fn(self)
    self.code = 400


@patch(FakeSecret._form_version_ids_to_stages, pass_target=False)
def _form_version_ids_to_stages_modal(self):
    version_id_to_stages: dict[str, list] = {}
    for key, value in self.versions.items():
        # Patch: include version_stages in the response only if it is not empty.
        if len(value["version_stages"]) > 0:
            version_id_to_stages[key] = value["version_stages"]
    return version_id_to_stages


# patching resource policy in moto
def get_resource_policy_model(self, secret_id):
    if self._is_valid_identifier(secret_id):
        result = {
            "ARN": self.secrets[secret_id].arn,
            "Name": self.secrets[secret_id].secret_id,
        }
        policy = getattr(self.secrets[secret_id], "policy", None)
        if policy:
            result["ResourcePolicy"] = policy
        return json.dumps(result)
    else:
        raise SecretNotFoundException()


def get_resource_policy_response(self):
    secret_id = self._get_param("SecretId")
    return self.backend.get_resource_policy(secret_id=secret_id)


def decode_secret_binary_from_response(response: dict[str, Any]):
    if "SecretBinary" in response:
        response["SecretBinary"] = base64.b64decode(response["SecretBinary"])

    return response


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
    return self.backend.delete_resource_policy(secret_id=secret_id)


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
    return self.backend.put_resource_policy(
        secret_id=secret_id, resource_policy=json.loads(resource_policy)
    )


def apply_patches():
    SecretsManagerBackend.get_resource_policy = get_resource_policy_model
    SecretsManagerResponse.get_resource_policy = get_resource_policy_response

    if not hasattr(SecretsManagerBackend, "delete_resource_policy"):
        SecretsManagerBackend.delete_resource_policy = delete_resource_policy_model
    if not hasattr(SecretsManagerResponse, "delete_resource_policy"):
        SecretsManagerResponse.delete_resource_policy = delete_resource_policy_response
    if not hasattr(SecretsManagerBackend, "put_resource_policy"):
        SecretsManagerBackend.put_resource_policy = put_resource_policy_model
    if not hasattr(SecretsManagerResponse, "put_resource_policy"):
        SecretsManagerResponse.put_resource_policy = put_resource_policy_response
