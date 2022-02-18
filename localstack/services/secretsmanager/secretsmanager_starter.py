import logging

from localstack.services.infra import start_moto_server
from localstack.services.secretsmanager.secretsmanager_patches import apply_patches
from localstack.utils.aws import aws_stack
from localstack.utils.common import wait_for_port_open

PORT_SECRETS_MANAGER_BACKEND = None


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
