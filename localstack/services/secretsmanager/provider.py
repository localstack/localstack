from __future__ import annotations

import json
import logging
import re
import time
from typing import Dict, Optional, Union

from moto.iam.policy_validation import IAMPolicyDocumentValidator
from moto.secretsmanager import models as secretsmanager_models
from moto.secretsmanager.exceptions import SecretNotFoundException, ValidationException
from moto.secretsmanager.models import FakeSecret, SecretsManagerBackend, secretsmanager_backends
from moto.secretsmanager.responses import SecretsManagerResponse

from localstack.aws.api import RequestContext, ServiceResponse, handler
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
from localstack.constants import TEST_AWS_ACCOUNT_ID
from localstack.services.moto import call_moto, call_moto_with_request
from localstack.utils.aws import aws_stack
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
def fake_secret__init__(fn, self, **kwargs):
    fn(self, **kwargs)

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
