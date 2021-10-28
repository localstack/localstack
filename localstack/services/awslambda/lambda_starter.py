import logging

from localstack import config

LOG = logging.getLogger(__name__)


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


def check_lambda(expect_shutdown=False, print_error=False):
    out = None
    try:
        from localstack.services.infra import PROXY_LISTENERS
        from localstack.utils.aws import aws_stack
        from localstack.utils.common import wait_for_port_open

        # wait for port to be opened
        port = PROXY_LISTENERS.get("lambda")[1]
        wait_for_port_open(port)  # TODO get lambda port in a cleaner way

        endpoint_url = f"http://127.0.0.1:{port}"
        out = aws_stack.connect_to_service(
            service_name="lambda", endpoint_url=endpoint_url
        ).list_functions()
    except Exception:
        if print_error:
            LOG.exception("Lambda health check failed")
    if expect_shutdown:
        assert out is None
    else:
        assert out and isinstance(out.get("Functions"), list)
