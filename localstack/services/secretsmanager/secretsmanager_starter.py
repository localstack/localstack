import logging
from moto.secretsmanager import models as secretsmanager_models
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
