from localstack import config
from localstack.services.infra import start_moto_server


def start_route53(port=None, asynchronous=False, update_listener=None):
    port = port or config.PORT_ROUTE53
    return start_moto_server(
        'route53', port, name='Route53',
        asynchronous=asynchronous, update_listener=update_listener
    )
