from __future__ import annotations

import json
import logging
import re
import time
from typing import Dict, Final, Optional, Union

from moto.awslambda.models import LambdaFunction
from moto.iam.policy_validation import IAMPolicyDocumentValidator
from moto.secretsmanager import models as secretsmanager_models
from moto.secretsmanager.models import FakeSecret, SecretsManagerBackend, secretsmanager_backends
from moto.secretsmanager.responses import SecretsManagerResponse

from localstack.aws.accounts import get_aws_account_id
from localstack.aws.api import CommonServiceException, RequestContext, ServiceResponse, handler
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
    ResourceNotFoundException,
    RestoreSecretRequest,
    RestoreSecretResponse,
    RotateSecretRequest,
    RotateSecretResponse,
    SecretIdType,
    SecretsmanagerApi,
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
from localstack.services.moto import call_moto, call_moto_with_request
from localstack.utils.aws import aws_stack
from localstack.utils.patch import patch
from localstack.utils.strings import short_uid
from localstack.utils.time import today_no_time

# Constants.
AWSPREVIOUS: Final[str] = "AWSPREVIOUS"
AWSPENDING: Final[str] = "AWSPENDING"
AWSCURRENT: Final[str] = "AWSCURRENT"

LOG = logging.getLogger(__name__)

# Maps key names to ARNs.
SECRET_ARN_STORAGE = {}


class ValidationException(CommonServiceException):
    def __init__(self, message: str):
        super().__init__("ValidationException", message, 400, True)


class SecretNotFoundException(CommonServiceException):
    def __init__(self, message: str):
        super().__init__("SecretNotFoundException", message, 404, True)


class SecretsmanagerProvider(SecretsmanagerApi):
    def __init__(self):
        super().__init__()
        apply_patches()

    @staticmethod
    def _transform_context_secret_id(secret_id: SecretIdType) -> Optional[SecretIdType]:
        # If secret ARN ends with "-<randomId>" this is removed from the request for upstream compatibility.
        t_secret_id = secret_id
        if secret_id and re.match(r"^arn:", secret_id):
            arn = aws_stack.parse_arn(secret_id)
            aws_region = aws_stack.get_region()
            if arn["region"] != aws_region:
                LOG.info(f'Expected request region "{aws_region}" for secret "{secret_id}"')
            resource_id = arn["resource"].split(":")[-1]
            if resource_id[-7] == "-":
                t_secret_id = resource_id[:-7]
            elif resource_id[-1] != "-":
                t_secret_id += "-"
        return None if secret_id == t_secret_id else t_secret_id

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
    def _call_moto_with_request_secret_id(
        context: RequestContext, request: Dict
    ) -> ServiceResponse:
        t_secret_id = SecretsmanagerProvider._transform_context_secret_id(
            request.get("SecretId", None)
        )
        if t_secret_id:
            request.update({"SecretId": t_secret_id})
            return call_moto_with_request(context, request)
        return call_moto(context)

    @handler("CancelRotateSecret", expand=False)
    def cancel_rotate_secret(
        self, context: RequestContext, request: CancelRotateSecretRequest
    ) -> CancelRotateSecretResponse:
        self._raise_if_invalid_secret_id(request["SecretId"])
        return self._call_moto_with_request_secret_id(context, request)

    @handler("CreateSecret", expand=False)
    def create_secret(
        self, context: RequestContext, request: CreateSecretRequest
    ) -> CreateSecretResponse:
        self._raise_if_invalid_secret_id(request["Name"])
        return call_moto(context)

    @handler("DeleteResourcePolicy", expand=False)
    def delete_resource_policy(
        self, context: RequestContext, request: DeleteResourcePolicyRequest
    ) -> DeleteResourcePolicyResponse:
        self._raise_if_invalid_secret_id(request["SecretId"])
        return self._call_moto_with_request_secret_id(context, request)

    @handler("DeleteSecret", expand=False)
    def delete_secret(
        self, context: RequestContext, request: DeleteSecretRequest
    ) -> DeleteSecretResponse:
        self._raise_if_invalid_secret_id(request["SecretId"])
        return self._call_moto_with_request_secret_id(context, request)

    @handler("DescribeSecret", expand=False)
    def describe_secret(
        self, context: RequestContext, request: DescribeSecretRequest
    ) -> DescribeSecretResponse:
        self._raise_if_invalid_secret_id(request["SecretId"])
        res = self._call_moto_with_request_secret_id(context, request)
        return res

    @handler("GetResourcePolicy", expand=False)
    def get_resource_policy(
        self, context: RequestContext, request: GetResourcePolicyRequest
    ) -> GetResourcePolicyResponse:
        self._raise_if_invalid_secret_id(request["SecretId"])
        return self._call_moto_with_request_secret_id(context, request)

    @handler("GetSecretValue", expand=False)
    def get_secret_value(
        self, context: RequestContext, request: GetSecretValueRequest
    ) -> GetSecretValueResponse:
        self._raise_if_invalid_secret_id(request["SecretId"])
        return self._call_moto_with_request_secret_id(context, request)

    @handler("ListSecretVersionIds", expand=False)
    def list_secret_version_ids(
        self, context: RequestContext, request: ListSecretVersionIdsRequest
    ) -> ListSecretVersionIdsResponse:
        self._raise_if_invalid_secret_id(request["SecretId"])
        return self._call_moto_with_request_secret_id(context, request)

    @handler("PutResourcePolicy", expand=False)
    def put_resource_policy(
        self, context: RequestContext, request: PutResourcePolicyRequest
    ) -> PutResourcePolicyResponse:
        self._raise_if_invalid_secret_id(request["SecretId"])
        return self._call_moto_with_request_secret_id(context, request)

    @handler("PutSecretValue", expand=False)
    def put_secret_value(
        self, context: RequestContext, request: PutSecretValueRequest
    ) -> PutSecretValueResponse:
        self._raise_if_invalid_secret_id(request["SecretId"])
        return self._call_moto_with_request_secret_id(context, request)

    @handler("RemoveRegionsFromReplication", expand=False)
    def remove_regions_from_replication(
        self, context: RequestContext, request: RemoveRegionsFromReplicationRequest
    ) -> RemoveRegionsFromReplicationResponse:
        self._raise_if_invalid_secret_id(request["SecretId"])
        return self._call_moto_with_request_secret_id(context, request)

    @handler("ReplicateSecretToRegions", expand=False)
    def replicate_secret_to_regions(
        self, context: RequestContext, request: ReplicateSecretToRegionsRequest
    ) -> ReplicateSecretToRegionsResponse:
        self._raise_if_invalid_secret_id(request["SecretId"])
        return self._call_moto_with_request_secret_id(context, request)

    @handler("RestoreSecret", expand=False)
    def restore_secret(
        self, context: RequestContext, request: RestoreSecretRequest
    ) -> RestoreSecretResponse:
        self._raise_if_invalid_secret_id(request["SecretId"])
        return self._call_moto_with_request_secret_id(context, request)

    @handler("RotateSecret", expand=False)
    def rotate_secret(
        self, context: RequestContext, request: RotateSecretRequest
    ) -> RotateSecretResponse:
        self._raise_if_invalid_secret_id(request["SecretId"])
        return self._call_moto_with_request_secret_id(context, request)

    @handler("StopReplicationToReplica", expand=False)
    def stop_replication_to_replica(
        self, context: RequestContext, request: StopReplicationToReplicaRequest
    ) -> StopReplicationToReplicaResponse:
        self._raise_if_invalid_secret_id(request["SecretId"])
        return self._call_moto_with_request_secret_id(context, request)

    @handler("TagResource", expand=False)
    def tag_resource(self, context: RequestContext, request: TagResourceRequest) -> None:
        self._raise_if_invalid_secret_id(request["SecretId"])
        return self._call_moto_with_request_secret_id(context, request)

    @handler("UntagResource", expand=False)
    def untag_resource(self, context: RequestContext, request: UntagResourceRequest) -> None:
        self._raise_if_invalid_secret_id(request["SecretId"])
        return self._call_moto_with_request_secret_id(context, request)

    @handler("UpdateSecret", expand=False)
    def update_secret(
        self, context: RequestContext, request: UpdateSecretRequest
    ) -> UpdateSecretResponse:
        self._raise_if_invalid_secret_id(request["SecretId"])
        return self._call_moto_with_request_secret_id(context, request)

    @handler("UpdateSecretVersionStage", expand=False)
    def update_secret_version_stage(
        self, context: RequestContext, request: UpdateSecretVersionStageRequest
    ) -> UpdateSecretVersionStageResponse:
        self._raise_if_invalid_secret_id(request["SecretId"])
        return self._call_moto_with_request_secret_id(context, request)

    @handler("ValidateResourcePolicy", expand=False)
    def validate_resource_policy(
        self, context: RequestContext, request: ValidateResourcePolicyRequest
    ) -> ValidateResourcePolicyResponse:
        self._raise_if_invalid_secret_id(request["SecretId"])
        return self._call_moto_with_request_secret_id(context, request)


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
        self.last_changed_date = time.time()


class FakeSecretVersionStore(dict):
    def __setitem__(self, key, value):
        self.put_version(key, value, time.time())

    def put_version(self, version_id: str, version: Dict, create_date: Optional[float] = None):
        if create_date and "createdate" in version:
            version["createdate"] = create_date
        super().__setitem__(version_id, version)


@patch(FakeSecret.set_versions)
def fake_secret_set_versions(_, self, versions):
    self.versions = FakeSecretVersionStore()
    for version_id, version in versions.items():
        self.versions.put_version(version_id, version, self.created_date)


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
    if not self.description and "Description" in res_dict:
        del res_dict["Description"]
    if not self.rotation_enabled and "RotationEnabled" in res_dict:
        del res_dict["RotationEnabled"]
    if self.auto_rotate_after_days is None and "RotationRules" in res_dict:
        del res_dict["RotationRules"]
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
    fn(self, secret_id, **kwargs)
    secret = self.secrets[secret_id]

    # Fix missing update of secret description.
    # Secret exists if this point is reached.
    if description is not None:
        secret.description = description

    return secret.to_short_dict()


@patch(SecretsManagerResponse.update_secret)
def response_update_secret(_, self):
    secret_id = self._get_param("SecretId")
    description = self._get_param("Description")
    secret_string = self._get_param("SecretString")
    secret_binary = self._get_param("SecretBinary")
    client_request_token = self._get_param("ClientRequestToken")
    kms_key_id = self._get_param("KmsKeyId")
    return secretsmanager_backends[self.region].update_secret(
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
    if version_stage == AWSCURRENT:
        secret.default_version_id = move_to_version_id

        # Ensure only one AWSPREVIOUS tagged version is in the pool.
        # Remove secret versions with no version stages.
        versions_no_stages = []
        update_vid_set = {remove_from_version_id, move_to_version_id}
        for version_id, version in secret.versions.items():
            version_stages = version["version_stages"]
            if version_id not in update_vid_set and AWSPREVIOUS in version_stages:
                version_stages.remove(AWSPREVIOUS)
                if not version_stages:
                    versions_no_stages.append(version_id)

        for version_no_stages in versions_no_stages:
            del secret.versions[version_no_stages]

    return json.dumps({"ARN": secret.arn, "Name": secret.name})


@patch(FakeSecret.reset_default_version)
def fake_secret_reset_default_version(fn, self, secret_version, version_id):
    fn(self, secret_version, version_id)
    # Remove versions with no version stages.
    versions_no_stages = [
        version_id for version_id, version in self.versions.items() if not version["version_stages"]
    ]
    for version_no_stages in versions_no_stages:
        del self.versions[version_no_stages]


@patch(FakeSecret.remove_version_stages_from_old_versions)
def fake_secret_remove_version_stages_from_old_versions(fn, self, version_stages):
    fn(self, version_stages)
    # Remove versions with no version stages.
    versions_no_stages = [
        version_id for version_id, version in self.versions.items() if not version["version_stages"]
    ]
    for version_no_stages in versions_no_stages:
        del self.versions[version_no_stages]


@patch(SecretsManagerBackend.rotate_secret)
def backend_rotate_secret(
    _,
    self,
    secret_id,
    client_request_token=None,
    rotation_lambda_arn=None,
    rotation_rules=None,
):
    rotation_days = "AutomaticallyAfterDays"

    if not self._is_valid_identifier(secret_id):
        raise SecretNotFoundException()

    if self.secrets[secret_id].is_deleted():
        raise InvalidRequestException(
            "An error occurred (InvalidRequestException) when calling the RotateSecret operation: You tried to \
            perform the operation on a secret that's currently marked deleted."
        )

    if rotation_lambda_arn:
        if len(rotation_lambda_arn) > 2048:
            msg = "RotationLambdaARN " "must <= 2048 characters long."
            raise InvalidParameterException(msg)

    if rotation_rules:
        if rotation_days in rotation_rules:
            rotation_period = rotation_rules[rotation_days]
            if rotation_period < 1 or rotation_period > 1000:
                msg = "RotationRules.AutomaticallyAfterDays " "must be within 1-1000."
                raise InvalidParameterException(msg)

    rotation_func = None
    try:
        lm_client = aws_stack.connect_to_service("lambda", region_name=self.region)
        get_func_res = lm_client.get_function(FunctionName=rotation_lambda_arn)
        lm_spec = get_func_res["Configuration"]
        lm_spec["Code"] = {"ZipFile": str(short_uid())}
        rotation_func = LambdaFunction(lm_spec, self.region)
    except Exception:
        # Fall through to ResourceNotFoundException.
        pass
    #
    if not rotation_func:
        raise ResourceNotFoundException("Lambda does not exist or could not be accessed")

    secret = self.secrets[secret_id]

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
        version = next(
            version
            for version in secret.versions.values()
            if AWSPENDING in version["version_stages"]
        )
        if AWSCURRENT in version["version_stages"]:
            msg = "Previous rotation request is still in progress."
            raise InvalidRequestException(msg)

    except StopIteration:
        # Pending is not present in any version
        pass

    # Begin the rotation process for the given secret by invoking the lambda function.
    #
    # We add the new secret version as "pending". The previous version remains
    # as "current" for now. Once we've passed the new secret through the lambda
    # rotation function (if provided) we can then update the status to "current".
    new_version_id = self._from_client_request_token(client_request_token)
    #
    self._add_secret(
        secret_id,
        None,
        description=secret.description,
        tags=secret.tags,
        version_id=new_version_id,
        version_stages=[AWSPENDING],
    )
    secret.rotation_lambda_arn = rotation_lambda_arn
    if rotation_rules:
        secret.auto_rotate_after_days = rotation_rules.get(rotation_days, 0)
    if secret.auto_rotate_after_days > 0:
        secret.rotation_enabled = True

    request_headers = {}
    response_headers = {}
    for step in ["create", "set", "test", "finish"]:
        rotation_func.invoke(
            json.dumps(
                {
                    "Step": step + "Secret",
                    "SecretId": secret.name,
                    "ClientRequestToken": new_version_id,
                }
            ),
            request_headers,
            response_headers,
        )

    secret.set_default_version_id(new_version_id)
    version_stages = secret.versions[new_version_id]["version_stages"]
    if AWSPENDING in version_stages:
        version_stages.remove(AWSPENDING)

    return secret.to_short_dict()


def secretsmanager_models_secret_arn(region, secret_id):
    k = f"{region}_{secret_id}"
    if k not in SECRET_ARN_STORAGE:
        id_string = short_uid()[:6]
        arn = aws_stack.secretsmanager_secret_arn(
            secret_id, account_id=get_aws_account_id(), region_name=region, random_suffix=id_string
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
        SecretsManagerBackend.delete_resource_policy = delete_resource_policy_model
    if not hasattr(SecretsManagerResponse, "delete_resource_policy"):
        SecretsManagerResponse.delete_resource_policy = delete_resource_policy_response
    if not hasattr(SecretsManagerBackend, "put_resource_policy"):
        SecretsManagerBackend.put_resource_policy = put_resource_policy_model
    if not hasattr(SecretsManagerResponse, "put_resource_policy"):
        SecretsManagerResponse.put_resource_policy = put_resource_policy_response
