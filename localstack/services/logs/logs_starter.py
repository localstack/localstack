from localstack import config
from localstack.services.infra import start_moto_server


def start_cloudwatch_logs(port=None, asynchronous=False, update_listener=None):
    port = port or config.PORT_LOGS
    return start_moto_server('logs', port, name='CloudWatch Logs',
        asynchronous=asynchronous, update_listener=update_listener)
