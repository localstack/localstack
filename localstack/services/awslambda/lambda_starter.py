import logging

from moto.awslambda import models as moto_awslambda_models

from localstack import config
from localstack.utils.aws import aws_stack
from localstack.utils.common import to_bytes
from localstack.utils.patch import patch

LOG = logging.getLogger(__name__)


# temporary state
TMP_STATE = {}
TMP_TAG = {}

# Key for tracking patch applience
PATCHES_APPLIED = "LAMBDA_PATCHED"


def start_lambda(port=None, asynchronous=False):
    from localstack.services.awslambda import lambda_api
    from localstack.services.infra import start_local_api

    apply_patches()

    port = port or config.service_port("lambda")
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
        # TODO get lambda port in a cleaner way
        port = PROXY_LISTENERS.get("lambda")[1]
        wait_for_port_open(port, sleep_time=0.5, retries=20)

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


def apply_patches():
    if TMP_STATE.get(PATCHES_APPLIED, False):
        return

    TMP_STATE[PATCHES_APPLIED] = True

    @patch(moto_awslambda_models.LambdaBackend.get_function)
    def get_function(fn, self, *args, **kwargs):
        result = fn(self, *args, **kwargs)
        if result:
            return result

        client = aws_stack.connect_to_service("lambda")
        lambda_name = aws_stack.lambda_function_name(args[0])
        response = client.get_function(FunctionName=lambda_name)

        spec = response["Configuration"]
        spec["Code"] = {"ZipFile": "ZW1wdHkgc3RyaW5n"}
        region = aws_stack.extract_region_from_arn(spec["FunctionArn"])
        new_function = moto_awslambda_models.LambdaFunction(spec, region)

        return new_function

    @patch(moto_awslambda_models.LambdaFunction.invoke)
    def invoke(fn, self, *args, **kwargs):
        payload = to_bytes(args[0])
        client = aws_stack.connect_to_service("lambda")
        return client.invoke(FunctionName=self.function_name, Payload=payload)
