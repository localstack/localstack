import logging
import json
from moto.secretsmanager import models as secretsmanager_models
from moto.secretsmanager.responses import SecretsManagerResponse
from moto.secretsmanager.models import secretsmanager_backends, SecretsManagerBackend
from moto.secretsmanager.exceptions import SecretNotFoundException
from moto.iam.policy_validation import IAMPolicyDocumentValidator
from localstack.services.infra import start_moto_server
from localstack.utils.aws import aws_stack

# maps key names to ARNs
SECRET_ARN_STORAGE = {}


def apply_patches():
    secret_arn_orig = secretsmanager_models.secret_arn

    def secretsmanager_models_secret_arn(region, secret_id):
        k = '{}_{}'.format(region, secret_id)
        if k not in SECRET_ARN_STORAGE:
            arn = secret_arn_orig(region, secret_id)
            SECRET_ARN_STORAGE[k] = arn

        return SECRET_ARN_STORAGE[k]

    secretsmanager_models.secret_arn = secretsmanager_models_secret_arn

    # patching resource policy in moto
    def get_resource_policy_model(self, secret_id):
        if self._is_valid_identifier(secret_id):
            result = {
                'ARN': self.secrets[secret_id].arn,
                'Name': self.secrets[secret_id].secret_id,
            }

            policy = getattr(self.secrets[secret_id], 'policy', None)
            if policy:
                result['ResourcePolicy'] = json.dumps(policy)

            return json.dumps(result)
        else:
            raise SecretNotFoundException()
    setattr(SecretsManagerBackend, 'get_resource_policy', get_resource_policy_model)

    def get_resource_policy_response(self):
        secret_id = self._get_param('SecretId')
        return secretsmanager_backends[self.region].get_resource_policy(
            secret_id=secret_id
        )
    setattr(SecretsManagerResponse, 'get_resource_policy', get_resource_policy_response)

    def delete_resource_policy_model(self, secret_id):
        if self._is_valid_identifier(secret_id):
            self.secrets[secret_id].policy = None
            return json.dumps(
                {
                    'ARN': self.secrets[secret_id].arn,
                    'Name': self.secrets[secret_id].secret_id
                }
            )
        else:
            raise SecretNotFoundException()
    if not hasattr(SecretsManagerBackend, 'delete_resource_policy'):
        setattr(SecretsManagerBackend, 'delete_resource_policy', delete_resource_policy_model)

    def delete_resource_policy_response(self):
        secret_id = self._get_param('SecretId')
        return secretsmanager_backends[self.region].delete_resource_policy(
            secret_id=secret_id
        )
    if not hasattr(SecretsManagerResponse, 'delete_resource_policy'):
        setattr(SecretsManagerResponse, 'delete_resource_policy', delete_resource_policy_response)

    def put_resource_policy_model(self, secret_id, resource_policy):
        policy_validator = IAMPolicyDocumentValidator(resource_policy)
        policy_validator._validate_top_elements()
        policy_validator._validate_version_syntax()
        if self._is_valid_identifier(secret_id):
            self.secrets[secret_id].policy = resource_policy
            return json.dumps(
                {
                    'ARN': self.secrets[secret_id].arn,
                    'Name': self.secrets[secret_id].secret_id
                }
            )
        else:
            raise SecretNotFoundException()
    if not hasattr(SecretsManagerBackend, 'put_resource_policy'):
        setattr(SecretsManagerBackend, 'put_resource_policy', put_resource_policy_model)

    def put_resource_policy_response(self):
        secret_id = self._get_param('SecretId')
        resource_policy = self._get_param('ResourcePolicy')
        return secretsmanager_backends[self.region].put_resource_policy(
            secret_id=secret_id,
            resource_policy=json.loads(resource_policy)
        )
    if not hasattr(SecretsManagerResponse, 'put_resource_policy'):
        setattr(SecretsManagerResponse, 'put_resource_policy', put_resource_policy_response)


def start_secretsmanager(port=None, asynchronous=None, backend_port=None, update_listener=None):
    apply_patches()
    return start_moto_server(
        key='secretsmanager',
        name='Secrets Manager',
        port=port,
        backend_port=backend_port,
        asynchronous=asynchronous,
        update_listener=update_listener
    )


def check_secretsmanager(expect_shutdown=False, print_error=False):
    out = None

    # noinspection PyBroadException
    try:
        out = aws_stack.connect_to_service(service_name='secretsmanager').list_secrets()
    except Exception:
        if print_error:
            logger = logging.getLogger(__name__)
            logger.exception('Secretsmanager health check failed')

    if expect_shutdown:
        assert out is None
        return

    assert isinstance(out['SecretList'], list)
