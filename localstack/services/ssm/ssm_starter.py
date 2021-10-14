from localstack import config


def start_ssm(port=None, asynchronous=False, update_listener=None):
    from localstack.services.infra import start_moto_server

    port = port or config.PORT_SSM
    return start_moto_server(
        "ssm",
        port,
        name="SSM",
        asynchronous=asynchronous,
        update_listener=update_listener,
    )
