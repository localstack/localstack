from localstack import config
from localstack.constants import DEFAULT_PORT_LOGS_BACKEND
from localstack.services.infra import start_moto_server


def start_cloudwatch_logs(port=None, asynchronous=False, update_listener=None):
    port = port or config.PORT_LOGS
    return start_moto_server('logs', port, name='CloudWatch Logs', asynchronous=asynchronous,
        backend_port=DEFAULT_PORT_LOGS_BACKEND, update_listener=update_listener)
