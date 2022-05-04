import base64
import logging
import os
import re
import time
from collections import defaultdict
from functools import lru_cache
from io import BytesIO
from typing import Any, Dict, List, Optional, Union

from flask import Response

from localstack import config
from localstack.utils import bootstrap
from localstack.utils.aws import aws_stack
from localstack.utils.aws.aws_models import LambdaFunction
from localstack.utils.aws.aws_responses import flask_error_response_json
from localstack.utils.common import short_uid, to_str
from localstack.utils.docker_utils import DOCKER_CLIENT

LOG = logging.getLogger(__name__)

# root path of Lambda API endpoints
API_PATH_ROOT = "/2015-03-31"

# Lambda runtime constants
LAMBDA_RUNTIME_PYTHON36 = "python3.6"
LAMBDA_RUNTIME_PYTHON37 = "python3.7"
LAMBDA_RUNTIME_PYTHON38 = "python3.8"
LAMBDA_RUNTIME_PYTHON39 = "python3.9"
LAMBDA_RUNTIME_NODEJS = "nodejs"
LAMBDA_RUNTIME_NODEJS10X = "nodejs10.x"
LAMBDA_RUNTIME_NODEJS12X = "nodejs12.x"
LAMBDA_RUNTIME_NODEJS14X = "nodejs14.x"
LAMBDA_RUNTIME_JAVA8 = "java8"
LAMBDA_RUNTIME_JAVA8_AL2 = "java8.al2"
LAMBDA_RUNTIME_JAVA11 = "java11"
LAMBDA_RUNTIME_DOTNETCORE2 = "dotnetcore2.0"
LAMBDA_RUNTIME_DOTNETCORE21 = "dotnetcore2.1"
LAMBDA_RUNTIME_DOTNETCORE31 = "dotnetcore3.1"
LAMBDA_RUNTIME_DOTNET6 = "dotnet6"
LAMBDA_RUNTIME_GOLANG = "go1.x"
LAMBDA_RUNTIME_RUBY = "ruby"
LAMBDA_RUNTIME_RUBY25 = "ruby2.5"
LAMBDA_RUNTIME_RUBY27 = "ruby2.7"
LAMBDA_RUNTIME_PROVIDED = "provided"
LAMBDA_RUNTIME_PROVIDED_AL2 = "provided.al2"

# default handler and runtime
LAMBDA_DEFAULT_HANDLER = "handler.handler"
LAMBDA_DEFAULT_RUNTIME = LAMBDA_RUNTIME_PYTHON37
LAMBDA_DEFAULT_STARTING_POSITION = "LATEST"

# List of Dotnet Lambda runtime names
DOTNET_LAMBDA_RUNTIMES = [
    LAMBDA_RUNTIME_DOTNETCORE2,
    LAMBDA_RUNTIME_DOTNETCORE21,
    LAMBDA_RUNTIME_DOTNETCORE31,
    LAMBDA_RUNTIME_DOTNET6,
]

# IP address of main Docker container (lazily initialized)
DOCKER_MAIN_CONTAINER_IP = None
LAMBDA_CONTAINER_NETWORK = None


class ClientError(Exception):
    def __init__(self, msg, code=400):
        super(ClientError, self).__init__(msg)
        self.code = code
        self.msg = msg

    def get_response(self):
        if isinstance(self.msg, Response):
            return self.msg
        return error_response(self.msg, self.code)


@lru_cache()
def get_default_executor_mode() -> str:
    """
    Returns the default docker executor mode, which is "docker" if the docker socket is available via the docker
    client, or "local"  otherwise.

    :return:
    """
    try:
        return "docker" if DOCKER_CLIENT.has_docker() else "local"
    except Exception:
        return "local"


def get_executor_mode() -> str:
    """
    Returns the currently active lambda executor mode. If config.LAMBDA_EXECUTOR is set, then it returns that,
    otherwise it falls back to get_default_executor_mode().

    :return: the lambda executor mode (e.g., 'local', 'docker', or 'docker-reuse')
    """
    return config.LAMBDA_EXECUTOR or get_default_executor_mode()


def multi_value_dict_for_list(elements: Union[List, Dict]) -> Dict:
    temp_mv_dict = defaultdict(list)
    for key in elements:
        if isinstance(key, (list, tuple)):
            key, value = key
        else:
            value = elements[key]
        key = to_str(key)
        temp_mv_dict[key].append(value)

    return dict((k, tuple(v)) for k, v in temp_mv_dict.items())


def get_lambda_runtime(runtime_details: Union[LambdaFunction, str]) -> str:
    """Return the runtime string from the given LambdaFunction (or runtime string)."""
    if isinstance(runtime_details, LambdaFunction):
        runtime_details = runtime_details.runtime
    if not isinstance(runtime_details, str):
        LOG.info("Unable to determine Lambda runtime from parameter: %s", runtime_details)
    return runtime_details or ""


def is_provided_runtime(runtime_details: Union[LambdaFunction, str]) -> bool:
    """Whether the given LambdaFunction uses a 'provided' runtime."""
    runtime = get_lambda_runtime(runtime_details) or ""
    return runtime.startswith("provided")


def format_name_to_path(handler_name: str, delimiter: str, extension: str):
    file_path = handler_name.rpartition(delimiter)[0]
    if delimiter == ":":
        file_path = file_path.split(delimiter)[0]

    if os.path.sep not in file_path:
        file_path = file_path.replace(".", os.path.sep)

    if file_path.startswith(f".{os.path.sep}"):
        file_path = file_path[2:]

    return f"{file_path}{extension}"


def get_handler_file_from_name(handler_name: str, runtime: str = None):
    runtime = runtime or LAMBDA_DEFAULT_RUNTIME

    if runtime.startswith(LAMBDA_RUNTIME_PROVIDED):
        return "bootstrap"
    if runtime.startswith(LAMBDA_RUNTIME_NODEJS):
        return format_name_to_path(handler_name, ".", ".js")
    if runtime.startswith(LAMBDA_RUNTIME_GOLANG):
        return handler_name
    if runtime.startswith(tuple(DOTNET_LAMBDA_RUNTIMES)):
        return format_name_to_path(handler_name, ":", ".dll")
    if runtime.startswith(LAMBDA_RUNTIME_RUBY):
        return format_name_to_path(handler_name, ".", ".rb")

    return format_name_to_path(handler_name, ".", ".py")


def is_java_lambda(lambda_details):
    runtime = getattr(lambda_details, "runtime", lambda_details)
    return runtime in [LAMBDA_RUNTIME_JAVA8, LAMBDA_RUNTIME_JAVA8_AL2, LAMBDA_RUNTIME_JAVA11]


def is_nodejs_runtime(lambda_details):
    runtime = getattr(lambda_details, "runtime", lambda_details) or ""
    return runtime.startswith("nodejs")


def is_python_runtime(lambda_details):
    runtime = getattr(lambda_details, "runtime", lambda_details) or ""
    return runtime.startswith("python")


def store_lambda_logs(
    lambda_function: LambdaFunction, log_output: str, invocation_time=None, container_id=None
):
    # leave here to avoid import issues from CLI
    from localstack.utils.cloudwatch.cloudwatch_util import store_cloudwatch_logs

    log_group_name = "/aws/lambda/%s" % lambda_function.name()
    container_id = container_id or short_uid()
    invocation_time = invocation_time or int(time.time() * 1000)
    invocation_time_secs = int(invocation_time / 1000)
    time_str = time.strftime("%Y/%m/%d", time.gmtime(invocation_time_secs))
    log_stream_name = "%s/[LATEST]%s" % (time_str, container_id)
    return store_cloudwatch_logs(log_group_name, log_stream_name, log_output, invocation_time)


def get_main_endpoint_from_container() -> str:
    global DOCKER_MAIN_CONTAINER_IP
    if not config.HOSTNAME_FROM_LAMBDA and DOCKER_MAIN_CONTAINER_IP is None:
        DOCKER_MAIN_CONTAINER_IP = False
        container_name = bootstrap.get_main_container_name()
        try:
            if config.is_in_docker:
                DOCKER_MAIN_CONTAINER_IP = DOCKER_CLIENT.get_container_ipv4_for_network(
                    container_name_or_id=container_name,
                    container_network=get_container_network_for_lambda(),
                )
            else:
                # default gateway for the network should be the host
                # (only under Linux - otherwise fall back to DOCKER_HOST_FROM_CONTAINER below)
                if config.is_in_linux:
                    DOCKER_MAIN_CONTAINER_IP = DOCKER_CLIENT.inspect_network(
                        get_container_network_for_lambda()
                    )["IPAM"]["Config"][0]["Gateway"]
            LOG.info("Determined main container target IP: %s", DOCKER_MAIN_CONTAINER_IP)
        except Exception as e:
            LOG.info(
                'Unable to get IP address of main Docker container "%s": %s', container_name, e
            )
    # return (1) predefined endpoint host, or (2) main container IP, or (3) Docker host (e.g., bridge IP)
    return (
        config.HOSTNAME_FROM_LAMBDA or DOCKER_MAIN_CONTAINER_IP or config.DOCKER_HOST_FROM_CONTAINER
    )


def get_container_network_for_lambda() -> str:
    global LAMBDA_CONTAINER_NETWORK
    if config.LAMBDA_DOCKER_NETWORK:
        return config.LAMBDA_DOCKER_NETWORK
    if LAMBDA_CONTAINER_NETWORK is None:
        try:
            if config.is_in_docker:
                networks = DOCKER_CLIENT.get_networks(bootstrap.get_main_container_name())
                LAMBDA_CONTAINER_NETWORK = networks[0]
            else:
                LAMBDA_CONTAINER_NETWORK = (
                    "bridge"  # use the default bridge network in case of host mode
                )
            LOG.info("Determined lambda container network: %s", LAMBDA_CONTAINER_NETWORK)
        except Exception as e:
            container_name = bootstrap.get_main_container_name()
            LOG.info('Unable to get network name of main container "%s": %s', container_name, e)
    return LAMBDA_CONTAINER_NETWORK


def rm_docker_container(container_name_or_id, check_existence=False, safe=False):
    # TODO: remove method / move to docker module
    if not container_name_or_id:
        return
    if check_existence and container_name_or_id not in DOCKER_CLIENT.get_running_container_names():
        # TODO: check names as well as container IDs!
        return
    try:
        DOCKER_CLIENT.remove_container(container_name_or_id)
    except Exception:
        if not safe:
            raise


def get_record_from_event(event: Dict, key: str) -> Any:
    """Retrieve a field with the given key from the list of Records within 'event'."""
    try:
        return event["Records"][0][key]
    except KeyError:
        return None


def get_zip_bytes(function_code):
    """Returns the ZIP file contents from a FunctionCode dict.

    :type function_code: dict
    :param function_code: https://docs.aws.amazon.com/lambda/latest/dg/API_FunctionCode.html
    :returns: bytes of the Zip file.
    """
    function_code = function_code or {}
    if "S3Bucket" in function_code:
        s3_client = aws_stack.connect_to_service("s3")
        bytes_io = BytesIO()
        try:
            s3_client.download_fileobj(function_code["S3Bucket"], function_code["S3Key"], bytes_io)
            zip_file_content = bytes_io.getvalue()
        except Exception as e:
            s3_key = str(function_code.get("S3Key") or "")
            s3_url = f's3://{function_code["S3Bucket"]}{s3_key if s3_key.startswith("/") else f"/{s3_key}"}'
            raise ClientError(f"Unable to fetch Lambda archive from {s3_url}: {e}", 404)
    elif "ZipFile" in function_code:
        zip_file_content = function_code["ZipFile"]
        zip_file_content = base64.b64decode(zip_file_content)
    elif "ImageUri" in function_code:
        zip_file_content = None
    else:
        raise ClientError("No valid Lambda archive specified: %s" % list(function_code.keys()))
    return zip_file_content


def event_source_arn_matches(mapped: str, searched: str) -> bool:
    if not mapped:
        return False
    if not searched or mapped == searched:
        return True
    # Some types of ARNs can end with a path separated by slashes, for
    # example the ARN of a DynamoDB stream is tableARN/stream/ID. It's
    # a little counterintuitive that a more specific mapped ARN can
    # match a less specific ARN on the event, but some integration tests
    # rely on it for things like subscribing to a stream and matching an
    # event labeled with the table ARN.
    if re.match(r"^%s$" % searched, mapped):
        return True
    if mapped.startswith(searched):
        suffix = mapped[len(searched) :]
        return suffix[0] == "/"
    return False


def error_response(msg, code=500, error_type="InternalFailure"):
    if code != 404:
        LOG.debug(msg)
    return flask_error_response_json(msg, code=code, error_type=error_type)


def generate_lambda_arn(
    account_id: int, region: str, fn_name: str, qualifier: Optional[str] = None
):
    if qualifier:
        return f"arn:aws:lambda:{region}:{account_id}:function:{fn_name}:{qualifier}"
    else:
        return f"arn:aws:lambda:{region}:{account_id}:function:{fn_name}"
