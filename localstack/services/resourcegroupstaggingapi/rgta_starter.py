from localstack import config
from localstack.services.infra import start_moto_server


def start_rgsa(port=None, asynchronous=False, update_listener=None):
    port = port or config.service_port("resourcegroupstaggingapi")

    return start_moto_server(
        "resourcegroupstaggingapi",
        port,
        name="Resource Groups Tagging API",
        asynchronous=asynchronous,
        update_listener=update_listener,
    )
