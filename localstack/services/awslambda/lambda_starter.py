from localstack import config


def start_lambda(port=None, asynchronous=False):
    from localstack.services.awslambda import lambda_api
    from localstack.services.infra import start_local_api

    port = port or config.PORT_LAMBDA
    return start_local_api(
        "Lambda", port, api="lambda", method=lambda_api.serve, asynchronous=asynchronous
    )


def stop_lambda() -> None:
    from localstack.services.awslambda.lambda_api import cleanup

    """
    Stops / cleans up the Lambda Executor
    """
    # TODO actually stop flask server
    cleanup()
