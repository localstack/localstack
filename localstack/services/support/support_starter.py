from localstack.services.infra import start_moto_server


def start_support(port=None, asynchronous=False):
    port = port
    return start_moto_server('support', port, name='Support', asynchronous=asynchronous)
