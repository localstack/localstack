from localstack import config


def start_firehose(port=None, asynchronous=False):
    from localstack.services.firehose import firehose_api
    from localstack.services.infra import start_local_api

    port = port or config.PORT_FIREHOSE
    return start_local_api(
        "Firehose",
        port,
        api="firehose",
        method=firehose_api.serve,
        asynchronous=asynchronous,
    )
