from localstack import config


def start_sns(port=None, asynchronous=False, update_listener=None):
    from localstack.services.infra import start_moto_server

    port = port or config.service_port("sns")
    return start_moto_server(
        "sns",
        port,
        name="SNS",
        asynchronous=asynchronous,
        update_listener=update_listener,
    )
