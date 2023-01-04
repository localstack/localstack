import base64
import json
import logging
import os
import re
import tempfile
import time
from functools import lru_cache
from io import BytesIO
from typing import Any, Dict, List, Optional, Union

from flask import Response

from localstack import config
from localstack.aws.accounts import get_aws_account_id
from localstack.aws.api.lambda_ import FilterCriteria, Runtime
from localstack.services.awslambda.lambda_models import AwsLambdaStore, awslambda_stores
from localstack.utils.aws import aws_stack
from localstack.utils.aws.arns import extract_account_id_from_arn, extract_region_from_arn
from localstack.utils.aws.aws_models import LambdaFunction
from localstack.utils.aws.aws_responses import flask_error_response_json
from localstack.utils.container_networking import (
    get_endpoint_for_network,
    get_main_container_network,
)
from localstack.utils.docker_utils import DOCKER_CLIENT
from localstack.utils.strings import first_char_to_lower, short_uid

LOG = logging.getLogger(__name__)

# root path of Lambda API endpoints
API_PATH_ROOT = "/2015-03-31"
API_PATH_ROOT_2 = "/2021-10-31"


# Lambda runtime constants (LEGACY, use values in Runtime class instead)
LAMBDA_RUNTIME_PYTHON37 = Runtime.python3_7
LAMBDA_RUNTIME_PYTHON38 = Runtime.python3_8
LAMBDA_RUNTIME_PYTHON39 = Runtime.python3_9
LAMBDA_RUNTIME_NODEJS = Runtime.nodejs
LAMBDA_RUNTIME_NODEJS12X = Runtime.nodejs12_x
LAMBDA_RUNTIME_NODEJS14X = Runtime.nodejs14_x
LAMBDA_RUNTIME_NODEJS16X = Runtime.nodejs16_x
LAMBDA_RUNTIME_JAVA8 = Runtime.java8
LAMBDA_RUNTIME_JAVA8_AL2 = Runtime.java8_al2
LAMBDA_RUNTIME_JAVA11 = Runtime.java11
LAMBDA_RUNTIME_DOTNETCORE31 = Runtime.dotnetcore3_1
LAMBDA_RUNTIME_DOTNET6 = Runtime.dotnet6
LAMBDA_RUNTIME_GOLANG = Runtime.go1_x
LAMBDA_RUNTIME_RUBY27 = Runtime.ruby2_7
LAMBDA_RUNTIME_PROVIDED = Runtime.provided
LAMBDA_RUNTIME_PROVIDED_AL2 = Runtime.provided_al2


# default handler and runtime
LAMBDA_DEFAULT_HANDLER = "handler.handler"
LAMBDA_DEFAULT_RUNTIME = LAMBDA_RUNTIME_PYTHON37  # FIXME (?)
LAMBDA_DEFAULT_STARTING_POSITION = "LATEST"

# List of Dotnet Lambda runtime names
DOTNET_LAMBDA_RUNTIMES = [
    LAMBDA_RUNTIME_DOTNETCORE31,
    LAMBDA_RUNTIME_DOTNET6,
]

# IP address of main Docker container (lazily initialized)
DOCKER_MAIN_CONTAINER_IP = None
LAMBDA_CONTAINER_NETWORK = None

FUNCTION_NAME_REGEX = re.compile(
    r"(arn:(aws[a-zA-Z-]*)?:lambda:)?((?P<region>[a-z]{2}(-gov)?-[a-z]+-\d{1}):)?(?P<account>\d{12}:)?(function:)?(?P<name>[a-zA-Z0-9-_\.]+)(:(?P<qualifier>\$LATEST|[a-zA-Z0-9-_]+))?"
)  # also length 1-170 incl.


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
    if runtime.startswith("nodejs"):
        return format_name_to_path(handler_name, ".", ".js")
    if runtime.startswith(LAMBDA_RUNTIME_GOLANG):
        return handler_name
    if runtime.startswith(tuple(DOTNET_LAMBDA_RUNTIMES)):
        return format_name_to_path(handler_name, ":", ".dll")
    if runtime.startswith("ruby"):
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
    if config.HOSTNAME_FROM_LAMBDA:
        return config.HOSTNAME_FROM_LAMBDA
    return get_endpoint_for_network(network=get_container_network_for_lambda())


def get_container_network_for_lambda() -> str:
    global LAMBDA_CONTAINER_NETWORK
    if config.LAMBDA_DOCKER_NETWORK:
        return config.LAMBDA_DOCKER_NETWORK
    return get_main_container_network()


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


def get_lambda_extraction_dir() -> str:
    """
    Get the directory a lambda is supposed to use as working directory (= the directory to extract the contents to).
    This method is needed due to performance problems for IO on bind volumes when running inside Docker Desktop, due to
    the file sharing with the host being slow when using gRPC-FUSE.
    By extracting to a not-mounted directory, we can improve performance significantly.
    The lambda zip file itself, however, should still be located on the mount.

    :return: directory path
    """
    if config.LAMBDA_REMOTE_DOCKER:
        return tempfile.gettempdir()
    return config.dirs.tmp


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


def parse_and_apply_numeric_filter(
    record_value: Dict, numeric_filter: List[Union[str, int]]
) -> bool:
    if len(numeric_filter) % 2 > 0:
        LOG.warn("Invalid numeric lambda filter given")
        return True

    if not isinstance(record_value, (int, float)):
        LOG.warn(f"Record {record_value} seem not to be a valid number")
        return False

    for idx in range(0, len(numeric_filter), 2):

        try:
            if numeric_filter[idx] == ">" and not (record_value > float(numeric_filter[idx + 1])):
                return False
            if numeric_filter[idx] == ">=" and not (record_value >= float(numeric_filter[idx + 1])):
                return False
            if numeric_filter[idx] == "=" and not (record_value == float(numeric_filter[idx + 1])):
                return False
            if numeric_filter[idx] == "<" and not (record_value < float(numeric_filter[idx + 1])):
                return False
            if numeric_filter[idx] == "<=" and not (record_value <= float(numeric_filter[idx + 1])):
                return False
        except ValueError:
            LOG.warn(
                f"Could not convert filter value {numeric_filter[idx + 1]} to a valid number value for filtering"
            )
    return True


def verify_dict_filter(record_value: any, dict_filter: Dict[str, any]) -> bool:
    # https://docs.aws.amazon.com/lambda/latest/dg/invocation-eventfiltering.html#filtering-syntax
    fits_filter = False
    for key, filter_value in dict_filter.items():
        if key.lower() == "anything-but":
            fits_filter = record_value not in filter_value
        elif key.lower() == "numeric":
            fits_filter = parse_and_apply_numeric_filter(record_value, filter_value)
        elif key.lower() == "exists":
            fits_filter = bool(filter_value)  # exists means that the key exists in the event record
        elif key.lower() == "prefix":
            if not isinstance(record_value, str):
                LOG.warn(f"Record Value {record_value} does not seem to be a valid string.")
            fits_filter = isinstance(record_value, str) and record_value.startswith(
                str(filter_value)
            )

        if fits_filter:
            return True
    return fits_filter


def filter_stream_record(filter_rule: Dict[str, any], record: Dict[str, any]) -> bool:
    if not filter_rule:
        return True
    # https://docs.aws.amazon.com/lambda/latest/dg/invocation-eventfiltering.html#filtering-syntax
    filter_results = []
    for key, value in filter_rule.items():
        # check if rule exists in event
        record_value = (
            record.get(key.lower(), record.get(key)) if isinstance(record, Dict) else None
        )
        append_record = False
        if record_value is not None:
            # check if filter rule value is a list (leaf of rule tree) or a dict (rescursively call function)
            if isinstance(value, list):
                if len(value) > 0:
                    if isinstance(value[0], (str, int)):
                        append_record = record_value in value
                    if isinstance(value[0], dict):
                        append_record = verify_dict_filter(record_value, value[0])
                else:
                    LOG.warn(f"Empty lambda filter: {key}")
            elif isinstance(value, dict):
                append_record = filter_stream_record(value, record_value)
        else:
            # special case 'exists'
            if isinstance(value, list) and len(value) > 0:
                append_record = not value[0].get("exists", True)

        filter_results.append(append_record)
    return all(filter_results)


def filter_stream_records(records, filters: List[FilterCriteria]):
    filtered_records = []
    for record in records:
        for filter in filters:
            for rule in filter["Filters"]:
                if filter_stream_record(json.loads(rule["Pattern"]), record):
                    filtered_records.append(record)
                    break
    return filtered_records


def contains_list(filter: Dict) -> bool:
    if isinstance(filter, dict):
        for key, value in filter.items():
            if isinstance(value, list) and len(value) > 0:
                return True
            return contains_list(value)
    return False


def validate_filters(filter: FilterCriteria) -> bool:
    # filter needs to be json serializeable
    for rule in filter["Filters"]:
        try:
            if not (filter_pattern := json.loads(rule["Pattern"])):
                return False
            return contains_list(filter_pattern)
        except json.JSONDecodeError:
            return False
    # needs to contain on what to filter (some list with citerias)
    # https://docs.aws.amazon.com/lambda/latest/dg/invocation-eventfiltering.html#filtering-syntax

    return True


def function_name_from_arn(arn: str):
    """Extract a function name from a arn/function name"""
    return FUNCTION_NAME_REGEX.match(arn).group("name")


def get_awslambda_store(
    account_id: Optional[str] = None, region: Optional[str] = None
) -> AwsLambdaStore:
    """Get the legacy Lambda store."""
    account_id = account_id or get_aws_account_id()
    region = region or aws_stack.get_region()

    return awslambda_stores[account_id][region]


def get_awslambda_store_for_arn(resource_arn: str) -> AwsLambdaStore:
    """
    Return the store for the region extracted from the given resource ARN.
    """
    return get_awslambda_store(
        account_id=extract_account_id_from_arn(resource_arn or ""),
        region=extract_region_from_arn(resource_arn or ""),
    )


def message_attributes_to_lower(message_attrs):
    """Convert message attribute details (first characters) to lower case (e.g., stringValue, dataType)."""
    message_attrs = message_attrs or {}
    for _, attr in message_attrs.items():
        if not isinstance(attr, dict):
            continue
        for key, value in dict(attr).items():
            attr[first_char_to_lower(key)] = attr.pop(key)
    return message_attrs
