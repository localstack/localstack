from localstack import config
from localstack.services.infra import start_moto_server


def start_rg(port=None, asynchronous=False, update_listener=None):
    port = port or config.PORT_RESOURCE_GROUPS

    return start_moto_server(
        "resource-groups",
        port,
        name="Resource Groups API",
        asynchronous=asynchronous,
        update_listener=update_listener,
    )
