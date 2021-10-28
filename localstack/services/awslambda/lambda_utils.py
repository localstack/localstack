import logging
import os
import time
from collections import defaultdict
from typing import Any, Dict, List, Union

from localstack import config
from localstack.utils import bootstrap
from localstack.utils.aws.aws_models import LambdaFunction
from localstack.utils.cloudwatch.cloudwatch_util import store_cloudwatch_logs
from localstack.utils.common import in_docker, short_uid, to_str
from localstack.utils.docker_utils import DOCKER_CLIENT

LOG = logging.getLogger(__name__)

# root path of Lambda API endpoints
API_PATH_ROOT = "/2015-03-31"

# Lambda runtime constants
LAMBDA_RUNTIME_PYTHON36 = "python3.6"
LAMBDA_RUNTIME_PYTHON37 = "python3.7"
LAMBDA_RUNTIME_PYTHON38 = "python3.8"
LAMBDA_RUNTIME_NODEJS = "nodejs"
LAMBDA_RUNTIME_NODEJS43 = "nodejs4.3"
LAMBDA_RUNTIME_NODEJS610 = "nodejs6.10"
LAMBDA_RUNTIME_NODEJS810 = "nodejs8.10"
LAMBDA_RUNTIME_NODEJS10X = "nodejs10.x"
LAMBDA_RUNTIME_NODEJS12X = "nodejs12.x"
LAMBDA_RUNTIME_NODEJS14X = "nodejs14.x"
LAMBDA_RUNTIME_JAVA8 = "java8"
LAMBDA_RUNTIME_JAVA8_AL2 = "java8.al2"
LAMBDA_RUNTIME_JAVA11 = "java11"
LAMBDA_RUNTIME_DOTNETCORE2 = "dotnetcore2.0"
LAMBDA_RUNTIME_DOTNETCORE21 = "dotnetcore2.1"
LAMBDA_RUNTIME_DOTNETCORE31 = "dotnetcore3.1"
LAMBDA_RUNTIME_GOLANG = "go1.x"
LAMBDA_RUNTIME_RUBY = "ruby"
LAMBDA_RUNTIME_RUBY25 = "ruby2.5"
LAMBDA_RUNTIME_RUBY27 = "ruby2.7"
LAMBDA_RUNTIME_PROVIDED = "provided"

# default handler and runtime
LAMBDA_DEFAULT_HANDLER = "handler.handler"
LAMBDA_DEFAULT_RUNTIME = LAMBDA_RUNTIME_PYTHON37
LAMBDA_DEFAULT_STARTING_POSITION = "LATEST"

# List of Dotnet Lambda runtime names
DOTNET_LAMBDA_RUNTIMES = [
    LAMBDA_RUNTIME_DOTNETCORE2,
    LAMBDA_RUNTIME_DOTNETCORE21,
    LAMBDA_RUNTIME_DOTNETCORE31,
]

# IP address of main Docker container (lazily initialized)
DOCKER_MAIN_CONTAINER_IP = None


def multi_value_dict_for_list(elements: List) -> Dict:
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


def get_handler_file_from_name(handler_name: str, runtime: str = None):
    runtime = runtime or LAMBDA_DEFAULT_RUNTIME
    if runtime.startswith(LAMBDA_RUNTIME_PROVIDED):
        return "bootstrap"
    delimiter = "."
    if runtime.startswith(LAMBDA_RUNTIME_NODEJS):
        file_ext = ".js"
    elif runtime.startswith(LAMBDA_RUNTIME_GOLANG):
        file_ext = ""
    elif runtime.startswith(tuple(DOTNET_LAMBDA_RUNTIMES)):
        file_ext = ".dll"
        delimiter = ":"
    elif runtime.startswith(LAMBDA_RUNTIME_RUBY):
        file_ext = ".rb"
    else:
        handler_name = handler_name.rpartition(delimiter)[0].replace(delimiter, os.path.sep)
        file_ext = ".py"
    return "%s%s" % (handler_name.split(delimiter)[0], file_ext)


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
    log_group_name = "/aws/lambda/%s" % lambda_function.name()
    container_id = container_id or short_uid()
    invocation_time = invocation_time or int(time.time() * 1000)
    invocation_time_secs = int(invocation_time / 1000)
    time_str = time.strftime("%Y/%m/%d", time.gmtime(invocation_time_secs))
    log_stream_name = "%s/[LATEST]%s" % (time_str, container_id)
    return store_cloudwatch_logs(log_group_name, log_stream_name, log_output, invocation_time)


def get_main_endpoint_from_container():
    global DOCKER_MAIN_CONTAINER_IP
    if not config.HOSTNAME_FROM_LAMBDA and DOCKER_MAIN_CONTAINER_IP is None:
        DOCKER_MAIN_CONTAINER_IP = False
        try:
            if in_docker():
                DOCKER_MAIN_CONTAINER_IP = bootstrap.get_main_container_ip()
                LOG.info("Determined main container target IP: %s" % DOCKER_MAIN_CONTAINER_IP)
        except Exception as e:
            container_name = bootstrap.get_main_container_name()
            LOG.info(
                'Unable to get IP address of main Docker container "%s": %s' % (container_name, e)
            )
    # return (1) predefined endpoint host, or (2) main container IP, or (3) Docker host (e.g., bridge IP)
    return (
        config.HOSTNAME_FROM_LAMBDA or DOCKER_MAIN_CONTAINER_IP or config.DOCKER_HOST_FROM_CONTAINER
    )


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
