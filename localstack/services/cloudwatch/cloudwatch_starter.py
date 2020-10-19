from localstack import config
from localstack.services.infra import start_moto_server


def start_cloudwatch(port=None, asynchronous=False, update_listener=None):
    port = port or config.PORT_CLOUDWATCH
    return start_moto_server(
        'cloudwatch', port, name='CloudWatch',
        update_listener=update_listener, asynchronous=asynchronous
    )
