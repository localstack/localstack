import logging

from moto.awslambda import models as moto_awslambda_models

from localstack import config
from localstack.services.awslambda.lambda_api import handle_lambda_url_invocation
from localstack.services.edge import ROUTER
from localstack.utils.aws import arns, aws_stack
from localstack.utils.aws.request_context import AWS_REGION_REGEX
from localstack.utils.patch import patch
from localstack.utils.platform import is_linux
from localstack.utils.strings import to_bytes

LOG = logging.getLogger(__name__)


# Key for tracking patch applience
PATCHES_APPLIED = "LAMBDA_PATCHED"


def start_lambda(port=None, asynchronous=False):
    from localstack.services.awslambda import lambda_api, lambda_utils
    from localstack.services.infra import start_local_api

    ROUTER.add(
        "/",
        host=f"<api_id>.lambda-url.<regex('{AWS_REGION_REGEX}'):region>.<regex('.*'):server>",
        endpoint=handle_lambda_url_invocation,
        defaults={"path": ""},
    )
    ROUTER.add(
        "/<path:path>",
        host=f"<api_id>.lambda-url.<regex('{AWS_REGION_REGEX}'):region>.<regex('.*'):server>",
        endpoint=handle_lambda_url_invocation,
    )

    # print a warning if we're not running in Docker but using Docker based LAMBDA_EXECUTOR
    if "docker" in lambda_utils.get_executor_mode() and not config.is_in_docker and not is_linux():
        LOG.warning(
            (
                "!WARNING! - Running outside of Docker with $LAMBDA_EXECUTOR=%s can lead to "
                "problems on your OS. The environment variable $LOCALSTACK_HOSTNAME may not "
                "be properly set in your Lambdas."
            ),
            lambda_utils.get_executor_mode(),
        )

    if (
        config.is_in_docker
        and not config.LAMBDA_REMOTE_DOCKER
        and not config.dirs.functions
        and config.LEGACY_DIRECTORIES
    ):
        LOG.warning(
            "!WARNING! - Looks like you have configured $LAMBDA_REMOTE_DOCKER=0 - "
            "please make sure to configure $HOST_TMP_FOLDER to point to your host's $TMPDIR"
        )

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


@patch(moto_awslambda_models.LambdaBackend.get_function)
def get_function(fn, self, *args, **kwargs):
    result = fn(self, *args, **kwargs)
    if result:
        return result

    client = aws_stack.connect_to_service("lambda")
    lambda_name = arns.lambda_function_name(args[0])
    response = client.get_function(FunctionName=lambda_name)

    spec = response["Configuration"]
    spec["Code"] = {"ZipFile": "ZW1wdHkgc3RyaW5n"}
    region = arns.extract_region_from_arn(spec["FunctionArn"])
    new_function = moto_awslambda_models.LambdaFunction(spec, region)

    return new_function


@patch(moto_awslambda_models.LambdaFunction.invoke)
def invoke(fn, self, *args, **kwargs):
    payload = to_bytes(args[0])
    client = aws_stack.connect_to_service("lambda")
    return client.invoke(FunctionName=self.function_name, Payload=payload)
