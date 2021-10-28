from localstack import config
from localstack.services.infra import start_moto_server


def start_sts(port=None, asynchronous=False, update_listener=None):
    port = port or config.PORT_STS

    return start_moto_server(
        "sts",
        port,
        name="STS",
        asynchronous=asynchronous,
        update_listener=update_listener,
    )
