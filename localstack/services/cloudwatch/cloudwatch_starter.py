from localstack import config
from localstack.services.infra import start_moto_server


def start_cloudwatch(port=None, asynchronous=False, update_listener=None):
    print('Deepak Starting cloudwatch')
    port = port or config.PORT_CLOUDWATCH
    return start_moto_server('cloudwatch', port, name='CloudWatch', asynchronous=asynchronous)
