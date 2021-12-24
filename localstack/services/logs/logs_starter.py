from localstack import config
from localstack.services.infra import start_moto_server
from localstack.services.logs import logs_listener
from localstack.utils.patch import Patches


def patch_logs():
    patches = Patches()
    logs_listener.add_patches(patches)
    patches.apply()


def start_cloudwatch_logs(port=None, asynchronous=False, update_listener=None):
    port = port or config.PORT_LOGS
    patch_logs()
    return start_moto_server(
        "logs",
        port,
        name="CloudWatch Logs",
        asynchronous=asynchronous,
        update_listener=update_listener,
    )
