import json
import logging
import random
import string

from moto.iam.policy_validation import IAMPolicyDocumentValidator
from moto.secretsmanager import models as secretsmanager_models
from moto.secretsmanager.exceptions import SecretNotFoundException
from moto.secretsmanager.models import SecretsManagerBackend, secretsmanager_backends, FakeSecret
from moto.secretsmanager.responses import SecretsManagerResponse

from localstack.constants import TEST_AWS_ACCOUNT_ID
from localstack.services.infra import start_moto_server
from localstack.utils.aws import aws_stack
from localstack.utils.common import wait_for_port_open

# maps key names to ARNs
SECRET_ARN_STORAGE = {}

PORT_SECRETS_MANAGER_BACKEND = None


def apply_patches():
    def secretsmanager_models_secret_arn(region, secret_id):
        k = "{}_{}".format(region, secret_id)
        if k not in SECRET_ARN_STORAGE:
            id_string = "".join(random.choice(string.ascii_letters) for _ in range(6))
            arn = "arn:aws:secretsmanager:{0}:{1}:secret:{2}-{3}".format(
                region, TEST_AWS_ACCOUNT_ID, secret_id, id_string
            )
            SECRET_ARN_STORAGE[k] = arn

        return SECRET_ARN_STORAGE[k]

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

    def put_secret_value(
            self,
            secret_id,
            secret_string,
            secret_binary,
            client_request_token,
            version_stages,
    ):
        # TODO: invoke moto implementation instead of overriding it completely? Check.
        if not self._is_valid_identifier(secret_id):
            raise SecretNotFoundException()
        else:
            secret = self.secrets[secret_id]
            tags = secret.tags
            description = secret.description

        secret: FakeSecret = self._add_secret(
            secret_id,
            secret_string,
            secret_binary,
            version_id=client_request_token,
            description=description,
            tags=tags,
            version_stages=version_stages,
        )

        stage_response: json = json.loads(secret.to_short_dict(include_version_stages=True))

        fake_secret_to_aws_key: dict[str, str] = {  # Not conversion to CamelCase on purpose: control these parameters.
            'version_id': 'VersionId',
            'version_stages': 'VersionStages'
        }
        #
        secret_versions_vs: [dict] = [v for v in secret.versions.values() if v['version_stages'] == version_stages]
        if secret_versions_vs:
            secret_version: dict = secret_versions_vs[0]  # TODO: what version if more than one?
            for skn, skn_aws in fake_secret_to_aws_key.items():
                if skn in secret_version and skn_aws in stage_response:
                    stage_response[skn_aws] = secret_version[skn]

        return json.dumps(stage_response)

    setattr(SecretsManagerBackend, 'put_secret_value', put_secret_value)

def start_secretsmanager(port=None, asynchronous=None, backend_port=None, update_listener=None):
    apply_patches()
    result = start_moto_server(
        key="secretsmanager",
        name="Secrets Manager",
        port=port,
        backend_port=backend_port,
        asynchronous=asynchronous,
        update_listener=update_listener,
    )
    global PORT_SECRETS_MANAGER_BACKEND
    PORT_SECRETS_MANAGER_BACKEND = result.service_port
    return result


def check_secretsmanager(expect_shutdown=False, print_error=False):
    out = None

    # noinspection PyBroadException
    try:
        wait_for_port_open(PORT_SECRETS_MANAGER_BACKEND, http_path="/", expect_success=False)
        endpoint_url = f"http://127.0.0.1:{PORT_SECRETS_MANAGER_BACKEND}"
        out = aws_stack.connect_to_service(
            service_name="secretsmanager", endpoint_url=endpoint_url
        ).list_secrets()
    except Exception:
        if print_error:
            logger = logging.getLogger(__name__)
            logger.exception("Secretsmanager health check failed")

    if expect_shutdown:
        assert out is None
        return

    assert isinstance(out["SecretList"], list)
