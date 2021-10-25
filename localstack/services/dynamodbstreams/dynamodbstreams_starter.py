from localstack import config


def start_dynamodbstreams(port=None, asynchronous=False):
    from localstack.services.dynamodbstreams import dynamodbstreams_api
    from localstack.services.infra import start_local_api

    port = port or config.PORT_DYNAMODBSTREAMS
    return start_local_api(
        "DynamoDB Streams",
        port,
        api="dynamodbstreams",
        method=dynamodbstreams_api.serve,
        asynchronous=asynchronous,
    )
