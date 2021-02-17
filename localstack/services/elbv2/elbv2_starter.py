from localstack import config
from localstack.services.infra import start_moto_server


def start_elbv2(port=None, asynchronous=False, update_listener=None):
    port = port or config.PORT_ELBV2

    return start_moto_server('elbv2', port, name='ELBv2', asynchronous=asynchronous, update_listener=update_listener)
