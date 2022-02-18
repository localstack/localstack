import json

from moto.secretsmanager.models import SecretsManagerBackend

from localstack.aws.api import RequestContext, handler
from localstack.aws.api.secretsmanager import (
    AddReplicaRegionListType,
    BooleanType,
    ClientRequestTokenType,
    CreateSecretResponse,
    DescriptionType,
    KmsKeyIdType,
    NameType,
    SecretBinaryType,
    SecretsmanagerApi,
    SecretStringType,
    TagListType,
)
from localstack.services import moto
from localstack.utils.aws import aws_stack


class SecretsmanagerProvider(SecretsmanagerApi):
    def __init__(self):
        # TODO: region?
        self.secretsmanager = SecretsManagerBackend(region_name=None)

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
        short_dict = self.secretsmanager.create_secret(
            name, secret_string, secret_binary, description, tags, kms_key_id
        )
        short_dict = json.loads(short_dict)
        # TODO: replication status?
        return CreateSecretResponse(
            ARN=short_dict["ARN"],
            Name=short_dict["Name"],
            VersionId=short_dict["VersionId"],
            ReplicationStatus=None,
        )
