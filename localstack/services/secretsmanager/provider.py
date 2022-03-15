import json
import logging
from typing import Dict, Optional

from moto.iam.policy_validation import IAMPolicyDocumentValidator
from moto.secretsmanager import models as secretsmanager_models
from moto.secretsmanager.exceptions import SecretNotFoundException
from moto.secretsmanager.models import SecretsManagerBackend, secretsmanager_backends
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
from localstack.utils.common import to_str
from localstack.utils.strings import short_uid

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
        if secret_id and ":" in secret_id:
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
    def _call_moto_with_request_secret_id(context: RequestContext) -> ServiceResponse:
        data_dict = SecretsmanagerProvider._transform_context_secret_id(context)
        return call_moto_with_request(context, data_dict) if data_dict else call_moto(context)

    @handler("CancelRotateSecret", expand=False)
    def cancel_rotate_secret(
        self, context: RequestContext, request: CancelRotateSecretRequest
    ) -> CancelRotateSecretResponse:
        return self._call_moto_with_request_secret_id(context)

    @handler("CreateSecret", expand=False)
    def create_secret(
        self, context: RequestContext, request: CreateSecretRequest
    ) -> CreateSecretResponse:
        return self._call_moto_with_request_secret_id(context)

    @handler("DeleteResourcePolicy", expand=False)
    def delete_resource_policy(
        self, context: RequestContext, request: DeleteResourcePolicyRequest
    ) -> DeleteResourcePolicyResponse:
        return self._call_moto_with_request_secret_id(context)

    @handler("DeleteSecret", expand=False)
    def delete_secret(
        self, context: RequestContext, request: DeleteSecretRequest
    ) -> DeleteSecretResponse:
        return self._call_moto_with_request_secret_id(context)

    @handler("DescribeSecret", expand=False)
    def describe_secret(
        self, context: RequestContext, request: DescribeSecretRequest
    ) -> DescribeSecretResponse:
        return self._call_moto_with_request_secret_id(context)

    @handler("GetResourcePolicy", expand=False)
    def get_resource_policy(
        self, context: RequestContext, request: GetResourcePolicyRequest
    ) -> GetResourcePolicyResponse:
        return self._call_moto_with_request_secret_id(context)

    @handler("GetSecretValue", expand=False)
    def get_secret_value(
        self, context: RequestContext, request: GetSecretValueRequest
    ) -> GetSecretValueResponse:
        return self._call_moto_with_request_secret_id(context)

    @handler("ListSecretVersionIds", expand=False)
    def list_secret_version_ids(
        self, context: RequestContext, request: ListSecretVersionIdsRequest
    ) -> ListSecretVersionIdsResponse:
        return self._call_moto_with_request_secret_id(context)

    @handler("PutResourcePolicy", expand=False)
    def put_resource_policy(
        self, context: RequestContext, request: PutResourcePolicyRequest
    ) -> PutResourcePolicyResponse:
        return self._call_moto_with_request_secret_id(context)

    @handler("PutSecretValue", expand=False)
    def put_secret_value(
        self, context: RequestContext, request: PutSecretValueRequest
    ) -> PutSecretValueResponse:
        return self._call_moto_with_request_secret_id(context)

    @handler("RemoveRegionsFromReplication", expand=False)
    def remove_regions_from_replication(
        self, context: RequestContext, request: RemoveRegionsFromReplicationRequest
    ) -> RemoveRegionsFromReplicationResponse:
        return self._call_moto_with_request_secret_id(context)

    @handler("ReplicateSecretToRegions", expand=False)
    def replicate_secret_to_regions(
        self, context: RequestContext, request: ReplicateSecretToRegionsRequest
    ) -> ReplicateSecretToRegionsResponse:
        return self._call_moto_with_request_secret_id(context)

    @handler("RestoreSecret", expand=False)
    def restore_secret(
        self, context: RequestContext, request: RestoreSecretRequest
    ) -> RestoreSecretResponse:
        return self._call_moto_with_request_secret_id(context)

    @handler("RotateSecret", expand=False)
    def rotate_secret(
        self, context: RequestContext, request: RotateSecretRequest
    ) -> RotateSecretResponse:
        return self._call_moto_with_request_secret_id(context)

    @handler("StopReplicationToReplica", expand=False)
    def stop_replication_to_replica(
        self, context: RequestContext, request: StopReplicationToReplicaRequest
    ) -> StopReplicationToReplicaResponse:
        return self._call_moto_with_request_secret_id(context)

    @handler("TagResource", expand=False)
    def tag_resource(self, context: RequestContext, request: TagResourceRequest) -> None:
        self._call_moto_with_request_secret_id(context)

    @handler("UntagResource", expand=False)
    def untag_resource(self, context: RequestContext, request: UntagResourceRequest) -> None:
        self._call_moto_with_request_secret_id(context)

    @handler("UpdateSecret", expand=False)
    def update_secret(
        self, context: RequestContext, request: UpdateSecretRequest
    ) -> UpdateSecretResponse:
        return self._call_moto_with_request_secret_id(context)

    @handler("UpdateSecretVersionStage", expand=False)
    def update_secret_version_stage(
        self, context: RequestContext, request: UpdateSecretVersionStageRequest
    ) -> UpdateSecretVersionStageResponse:
        return self._call_moto_with_request_secret_id(context)

    @handler("ValidateResourcePolicy", expand=False)
    def validate_resource_policy(
        self, context: RequestContext, request: ValidateResourcePolicyRequest
    ) -> ValidateResourcePolicyResponse:
        return self._call_moto_with_request_secret_id(context)


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
