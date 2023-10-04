import ast
import base64
import functools
import hashlib
import importlib.machinery
import json
import logging
import os
import re
import sys
import threading
import time
import traceback
import urllib.parse
import uuid
from datetime import datetime
from io import StringIO
from json import JSONDecodeError
from random import random
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from flask import Flask, Response, jsonify, request
from flask_cors import CORS

from localstack import config, constants
from localstack.aws.accounts import get_aws_account_id
from localstack.aws.connect import connect_to
from localstack.constants import APPLICATION_JSON
from localstack.http import Request
from localstack.http import Response as HttpResponse
from localstack.services.lambda_ import lambda_executors
from localstack.services.lambda_.event_source_listeners.event_source_listener import (
    EventSourceListener,
)
from localstack.services.lambda_.lambda_executors import InvocationResult, LambdaContext
from localstack.services.lambda_.lambda_models import lambda_stores_v1
from localstack.services.lambda_.lambda_utils import (
    API_PATH_ROOT,
    API_PATH_ROOT_2,
    DOTNET_LAMBDA_RUNTIMES,
    LAMBDA_DEFAULT_HANDLER,
    LAMBDA_DEFAULT_RUNTIME,
    LAMBDA_RUNTIME_NODEJS14X,
    ClientError,
    error_response,
    event_source_arn_matches,
    function_name_from_arn,
    get_executor_mode,
    get_handler_file_from_name,
    get_lambda_extraction_dir,
    get_lambda_runtime,
    get_lambda_store_v1,
    get_lambda_store_v1_for_arn,
    get_zip_bytes,
    validate_filters,
)
from localstack.services.lambda_.packages import lambda_go_runtime_package
from localstack.utils.archives import unzip
from localstack.utils.aws import arns, aws_stack, resources
from localstack.utils.aws.arns import extract_region_from_arn
from localstack.utils.aws.aws_models import CodeSigningConfig, InvalidEnvVars, LambdaFunction
from localstack.utils.aws.aws_responses import ResourceNotFoundException
from localstack.utils.common import get_unzipped_size, is_zip_file
from localstack.utils.container_networking import get_main_container_name
from localstack.utils.docker_utils import DOCKER_CLIENT
from localstack.utils.files import TMP_FILES, ensure_readable, load_file, mkdir, save_file
from localstack.utils.functions import empty_context_manager, run_safe
from localstack.utils.http import parse_chunked_data, safe_requests
from localstack.utils.json import json_safe
from localstack.utils.patch import patch
from localstack.utils.run import run, run_for_max_seconds
from localstack.utils.ssl import create_ssl_cert
from localstack.utils.strings import long_uid, md5, short_uid, to_bytes, to_str
from localstack.utils.sync import synchronized
from localstack.utils.threads import start_thread
from localstack.utils.time import (
    TIMESTAMP_FORMAT_MICROS,
    TIMESTAMP_READABLE_FORMAT,
    isoformat_milliseconds,
    mktime,
    now_utc,
    timestamp,
)
from localstack.utils.urls import localstack_host

LOG = logging.getLogger(__name__)

# name pattern of IAM policies associated with Lambda functions (name/qualifier)
LAMBDA_POLICY_NAME_PATTERN = "lambda_policy_{name}_{qualifier}"
LAMBDA_TEST_ROLE = "arn:aws:iam::{account_id}:role/lambda-test-role"

# constants
APP_NAME = "lambda_api"
ARCHIVE_FILE_PATTERN = "%s/lambda.handler.*.jar" % config.dirs.tmp
LAMBDA_SCRIPT_PATTERN = "%s/lambda_script_*.py" % config.dirs.tmp
LAMBDA_ZIP_FILE_NAME = "original_lambda_archive.zip"
LAMBDA_JAR_FILE_NAME = "original_lambda_archive.jar"

# default timeout in seconds
LAMBDA_DEFAULT_TIMEOUT = 3

INVALID_PARAMETER_VALUE_EXCEPTION = "InvalidParameterValueException"
VERSION_LATEST = LambdaFunction.QUALIFIER_LATEST
FUNCTION_MAX_SIZE = 69905067
FUNCTION_MAX_UNZIPPED_SIZE = 262144000

BATCH_SIZE_RANGES = {
    "kafka": (100, 10000),
    "kinesis": (100, 10000),
    "dynamodb": (100, 1000),
    "sqs": (
        10,
        10,
    ),  # should be (10,10000) for normal SQS queues, (10,10) for FIFO https://docs.aws.amazon.com/lambda/latest/dg/API_CreateEventSourceMapping.html#SSS-CreateEventSourceMapping-request-BatchSize
}

DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%f+00:00"

app = Flask(APP_NAME)


@patch(app.route)
def app_route(self, fn, *args, **kwargs):
    # make sure all routes can be called with/without trailing slashes, without triggering 308 forwards
    return fn(*args, strict_slashes=False, **kwargs)


# mutex for access to CWD and ENV
EXEC_MUTEX = threading.RLock()

# whether to use Docker for execution
DO_USE_DOCKER = None

# start characters indicating that a lambda result should be parsed as JSON
JSON_START_CHAR_MAP = {
    list: ("[",),
    tuple: ("[",),
    dict: ("{",),
    str: ('"',),
    bytes: ('"',),
    bool: ("t", "f"),
    type(None): ("n",),
    int: ("0", "1", "2", "3", "4", "5", "6", "7", "8", "9"),
    float: ("0", "1", "2", "3", "4", "5", "6", "7", "8", "9"),
}
POSSIBLE_JSON_TYPES = (str, bytes)
JSON_START_TYPES = tuple(set(JSON_START_CHAR_MAP.keys()) - set(POSSIBLE_JSON_TYPES))
JSON_START_CHARS = tuple(set(functools.reduce(lambda x, y: x + y, JSON_START_CHAR_MAP.values())))

# lambda executor instance
LAMBDA_EXECUTOR = lambda_executors.AVAILABLE_EXECUTORS.get(
    get_executor_mode(), lambda_executors.DEFAULT_EXECUTOR
)

# IAM policy constants
IAM_POLICY_VERSION = "2012-10-17"

# Whether to check if the handler function exists while creating lambda function
CHECK_HANDLER_ON_CREATION = False


def cleanup():
    store = get_lambda_store_v1()
    store.lambdas.clear()
    store.event_source_mappings.clear()
    LAMBDA_EXECUTOR.cleanup()


def func_arn(function_name, remove_qualifier=True):
    parts = function_name.split(":function:")
    if remove_qualifier and len(parts) > 1:
        function_name = "%s:function:%s" % (parts[0], parts[1].split(":")[0])
    return arns.lambda_function_arn(function_name)


def func_qualifier(function_name, qualifier=None):
    store = get_lambda_store_v1_for_arn(function_name)
    arn = arns.lambda_function_arn(function_name)
    details = store.lambdas.get(arn)
    if not details:
        return details
    if details.qualifier_exists(qualifier):
        return "{}:{}".format(arn, qualifier)
    return arn


def check_batch_size_range(source_arn, batch_size=None):
    source = source_arn.split(":")[2].lower()
    source = "kafka" if "secretsmanager" in source else source
    batch_size_entry = BATCH_SIZE_RANGES.get(source)
    if not batch_size_entry:
        raise ValueError(INVALID_PARAMETER_VALUE_EXCEPTION, "Unsupported event source type")

    batch_size = batch_size or batch_size_entry[0]
    if batch_size > batch_size_entry[1]:
        raise ValueError(
            INVALID_PARAMETER_VALUE_EXCEPTION,
            "BatchSize {} exceeds the max of {}".format(batch_size, batch_size_entry[1]),
        )

    return batch_size


def build_mapping_obj(data) -> Dict:
    mapping = {}
    function_name = data["FunctionName"]
    enabled = data.get("Enabled", True)
    batch_size = data.get("BatchSize")
    mapping["UUID"] = str(uuid.uuid4())
    mapping["FunctionArn"] = func_arn(function_name)
    mapping["LastProcessingResult"] = "OK"
    mapping["StateTransitionReason"] = "User action"
    mapping["LastModified"] = format_timestamp_for_event_source_mapping()
    mapping["State"] = "Enabled" if enabled in [True, None] else "Disabled"
    mapping["ParallelizationFactor"] = data.get("ParallelizationFactor") or 1
    mapping["Topics"] = data.get("Topics") or []
    mapping["MaximumRetryAttempts"] = data.get("MaximumRetryAttempts") or -1
    if "SelfManagedEventSource" in data:
        source_arn = data["SourceAccessConfigurations"][0]["URI"]
        mapping["SelfManagedEventSource"] = data["SelfManagedEventSource"]
        mapping["SourceAccessConfigurations"] = data["SourceAccessConfigurations"]
    else:
        source_arn = data["EventSourceArn"]
        mapping["EventSourceArn"] = source_arn
        mapping["StartingPosition"] = data.get("StartingPosition") or "LATEST"
    batch_size = check_batch_size_range(source_arn, batch_size)
    mapping["BatchSize"] = batch_size

    if data.get("DestinationConfig"):
        mapping["DestinationConfig"] = data.get("DestinationConfig")

    if data.get("FunctionResponseTypes"):
        mapping["FunctionResponseTypes"] = data.get("FunctionResponseTypes")

    if data.get("FilterCriteria"):
        # validate for valid json
        if not validate_filters(data.get("FilterCriteria")):
            # AWS raises following Exception when FilterCriteria is not valid:
            # An error occurred (InvalidParameterValueException) when calling the CreateEventSourceMapping operation:
            # Invalid filter pattern definition.
            raise ValueError(
                INVALID_PARAMETER_VALUE_EXCEPTION, "Invalid filter pattern definition."
            )
        mapping["FilterCriteria"] = data.get("FilterCriteria")
    return mapping


def is_hot_reloading(code: dict) -> bool:
    bucket_name = code.get("S3Bucket")
    if (
        bucket_name == constants.LEGACY_DEFAULT_BUCKET_MARKER_LOCAL
        and bucket_name != config.BUCKET_MARKER_LOCAL
    ):
        LOG.warning(
            "Please note that using %s as local bucket marker is deprecated. Please use %s or set the config option 'BUCKET_MARKER_LOCAL'",
            constants.LEGACY_DEFAULT_BUCKET_MARKER_LOCAL,
            constants.DEFAULT_BUCKET_MARKER_LOCAL,
        )
        return True
    return code.get("S3Bucket") == config.BUCKET_MARKER_LOCAL


def format_timestamp(timestamp=None):
    timestamp = timestamp or datetime.utcnow()
    return isoformat_milliseconds(timestamp) + "+0000"


def format_timestamp_for_event_source_mapping():
    # event source mappings seem to use a different time format (required for Terraform compat.)
    return datetime.utcnow().timestamp()


def add_event_source(data):
    store = get_lambda_store_v1()
    mapping = build_mapping_obj(data)
    store.event_source_mappings.append(mapping)
    EventSourceListener.start_listeners(mapping)
    return mapping


def update_event_source(uuid_value, data):
    function_name = data.get("FunctionName") or ""
    store = get_lambda_store_v1_for_arn(function_name)
    enabled = data.get("Enabled", True)
    for mapping in store.event_source_mappings:
        if uuid_value == mapping["UUID"]:
            if function_name:
                mapping["FunctionArn"] = func_arn(function_name)
            batch_size = data.get("BatchSize")
            if "SelfManagedEventSource" in mapping:
                batch_size = check_batch_size_range(
                    mapping["SourceAccessConfigurations"][0]["URI"],
                    batch_size or mapping["BatchSize"],
                )
            else:
                batch_size = check_batch_size_range(
                    mapping["EventSourceArn"], batch_size or mapping["BatchSize"]
                )
            mapping["State"] = "Enabled" if enabled in [True, None] else "Disabled"
            mapping["LastModified"] = format_timestamp_for_event_source_mapping()
            mapping["BatchSize"] = batch_size
            if "SourceAccessConfigurations" in (mapping and data):
                mapping["SourceAccessConfigurations"] = data["SourceAccessConfigurations"]
            return mapping
    return {}


def delete_event_source(uuid_value: str):
    store = get_lambda_store_v1()
    for i, m in enumerate(store.event_source_mappings):
        if uuid_value == m["UUID"]:
            return store.event_source_mappings.pop(i)
    return {}


def get_lambda_event_filters_for_arn(lambda_arn: str, event_arn: str) -> List[Dict]:
    region_name = lambda_arn.split(":")[3]
    region = get_lambda_store_v1(region=region_name)

    event_filter_criterias = [
        event_source_mapping.get("FilterCriteria")
        for event_source_mapping in region.event_source_mappings
        if event_source_mapping.get("FunctionArn") == lambda_arn
        and event_source_mapping.get("EventSourceArn") == event_arn
        and event_source_mapping.get("FilterCriteria") is not None
    ]

    return event_filter_criterias


@synchronized(lock=EXEC_MUTEX)
def use_docker():
    global DO_USE_DOCKER
    if DO_USE_DOCKER is None:
        DO_USE_DOCKER = False
        if "docker" in get_executor_mode():
            has_docker = DOCKER_CLIENT.has_docker()
            if not has_docker:
                LOG.warning(
                    (
                        "Lambda executor configured as LAMBDA_EXECUTOR=%s but Docker "
                        "is not accessible. Please make sure to mount the Docker socket "
                        "/var/run/docker.sock into the container."
                    ),
                    get_executor_mode(),
                )
            DO_USE_DOCKER = has_docker
    return DO_USE_DOCKER


def process_lambda_url_invocation(lambda_url_config: dict, event: dict):
    inv_result = run_lambda(
        func_arn=lambda_url_config["FunctionArn"],
        event=event,
        asynchronous=False,
    )
    return inv_result.result


def get_event_sources(func_name=None, source_arn=None) -> list:
    result = []
    for store in lambda_stores_v1[get_aws_account_id()].values():
        for m in store.event_source_mappings:
            if not func_name or (m["FunctionArn"] in [func_name, func_arn(func_name)]):
                if event_source_arn_matches(mapped=m.get("EventSourceArn"), searched=source_arn):
                    result.append(m)
    return result


def get_function_version(arn, version):
    store = get_lambda_store_v1_for_arn(arn)
    func = store.lambdas.get(arn)
    return format_func_details(func, version=version, always_add_version=True)


def publish_new_function_version(arn: str):
    store = get_lambda_store_v1_for_arn(arn)
    lambda_function = store.lambdas.get(arn)
    versions = lambda_function.versions
    max_version_number = lambda_function.max_version()
    next_version_number = max_version_number + 1
    latest_hash = versions.get(VERSION_LATEST).get("CodeSha256")
    max_version = versions.get(str(max_version_number))
    max_version_hash = max_version.get("CodeSha256") if max_version else ""

    if latest_hash != max_version_hash:
        versions[str(next_version_number)] = {
            "CodeSize": versions.get(VERSION_LATEST).get("CodeSize"),
            "CodeSha256": versions.get(VERSION_LATEST).get("CodeSha256"),
            "Function": versions.get(VERSION_LATEST).get("Function"),
            "RevisionId": str(uuid.uuid4()),
        }
        max_version_number = next_version_number
    return get_function_version(arn, str(max_version_number))


def do_list_versions(arn: str):
    store = get_lambda_store_v1_for_arn(arn)
    versions = [
        get_function_version(arn, version) for version in store.lambdas.get(arn).versions.keys()
    ]
    return sorted(versions, key=lambda k: str(k.get("Version")))


def do_update_alias(arn: str, alias: str, version: str, description=None):
    store = get_lambda_store_v1_for_arn(arn)
    new_alias = {
        "AliasArn": arn + ":" + alias,
        "FunctionVersion": version,
        "Name": alias,
        "Description": description or "",
        "RevisionId": str(uuid.uuid4()),
    }
    store.lambdas.get(arn).aliases[alias] = new_alias
    return new_alias


def run_lambda(
    func_arn: str,
    event,
    context=None,
    version: Optional[str] = None,
    suppress_output: bool = False,
    asynchronous: bool = False,
    callback: Optional[Callable] = None,
    lock_discriminator: str = None,
) -> InvocationResult:
    if context is None:
        context = {}

    # Ensure that the service provider has been initialized. This is required to ensure all lifecycle hooks
    # (e.g., persistence) have been executed when the run_lambda(..) function gets called (e.g., from API GW).
    LOG.debug("Running lambda %s", func_arn)
    if not hasattr(run_lambda, "_provider_initialized"):
        connect_to().lambda_.list_functions()
        run_lambda._provider_initialized = True

    store = get_lambda_store_v1_for_arn(func_arn)
    if suppress_output:
        stdout_ = sys.stdout
        stderr_ = sys.stderr
        stream = StringIO()
        sys.stdout = stream
        sys.stderr = stream
    try:
        func_arn = arns.fix_arn(func_arn)
        lambda_function = store.lambdas.get(func_arn)
        if not lambda_function:
            region_name = extract_region_from_arn(func_arn)
            LOG.debug("Unable to find details for Lambda %s in region %s", func_arn, region_name)
            result = not_found_error(msg="The resource specified in the request does not exist.")
            return InvocationResult(result)

        if lambda_function.state != "Active":
            result = error_response(
                f"The operation cannot be performed at this time. The function is currently in the following state: {lambda_function.state}",
                409,
                "ResourceConflictException",
            )
            raise ClientError(result)

        context = LambdaContext(lambda_function, version, context)
        result = LAMBDA_EXECUTOR.execute(
            func_arn,
            lambda_function,
            event,
            context=context,
            version=version,
            asynchronous=asynchronous,
            callback=callback,
            lock_discriminator=lock_discriminator,
        )
        return result
    except ClientError:
        raise
    except Exception as e:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        response = {
            "errorType": str(exc_type.__name__),
            "errorMessage": str(e),
            "stackTrace": traceback.format_tb(exc_traceback),
        }
        LOG.info("Error executing Lambda function %s: %s %s", func_arn, e, traceback.format_exc())
        if isinstance(e, lambda_executors.InvocationException):
            exc_result = e.result
            response = run_safe(lambda: json.loads(exc_result)) or response
        log_output = e.log_output if isinstance(e, lambda_executors.InvocationException) else ""
        return InvocationResult(Response(json.dumps(response), status=500), log_output)
    finally:
        if suppress_output:
            sys.stdout = stdout_
            sys.stderr = stderr_


def load_source(name, file):
    return importlib.machinery.SourceFileLoader(name, file).load_module()


def exec_lambda_code(script, handler_function="handler", lambda_cwd=None, lambda_env=None):
    # TODO: The code in this function is generally not thread-safe and potentially insecure
    #  (e.g., mutating environment variables, and globally loaded modules). Should be redesigned.

    def _do_exec_lambda_code():
        import os as exec_os
        import sys as exec_sys

        if lambda_cwd or lambda_env:
            if lambda_cwd:
                previous_cwd = exec_os.getcwd()
                exec_os.chdir(lambda_cwd)
                exec_sys.path = [lambda_cwd] + exec_sys.path
            if lambda_env:
                previous_env = dict(exec_os.environ)
                exec_os.environ.update(lambda_env)
        # generate lambda file name
        lambda_id = "l_%s" % short_uid()
        lambda_file = LAMBDA_SCRIPT_PATTERN.replace("*", lambda_id)
        save_file(lambda_file, script)
        # delete temporary .py and .pyc files on exit
        TMP_FILES.append(lambda_file)
        TMP_FILES.append("%sc" % lambda_file)
        try:
            pre_sys_modules_keys = set(exec_sys.modules.keys())
            # set default env variables required for most Lambda handlers
            env_vars_before = lambda_executors.LambdaExecutorLocal.set_default_env_variables()
            try:
                handler_module = load_source(lambda_id, lambda_file)
                module_vars = handler_module.__dict__
            finally:
                lambda_executors.LambdaExecutorLocal.reset_default_env_variables(env_vars_before)
                # the above import can bring files for the function
                # (eg settings.py) into the global namespace. subsequent
                # calls can pick up file from another function, causing
                # general issues.
                post_sys_modules_keys = set(exec_sys.modules.keys())
                for key in post_sys_modules_keys:
                    if key not in pre_sys_modules_keys:
                        exec_sys.modules.pop(key)
        except Exception as e:
            LOG.error("Unable to exec: %s %s", script, traceback.format_exc())
            raise e
        finally:
            if lambda_cwd or lambda_env:
                if lambda_cwd:
                    exec_os.chdir(previous_cwd)
                    exec_sys.path.pop(0)
                if lambda_env:
                    exec_os.environ = previous_env
        return module_vars[handler_function]

    lock = EXEC_MUTEX if lambda_cwd or lambda_env else empty_context_manager()
    with lock:
        return _do_exec_lambda_code()


def get_handler_function_from_name(handler_name, runtime=None):
    runtime = runtime or LAMBDA_DEFAULT_RUNTIME
    if runtime.startswith(tuple(DOTNET_LAMBDA_RUNTIMES)):
        return handler_name.split(":")[-1]
    return handler_name.split(".")[-1]


def get_java_handler(zip_file_content, main_file, lambda_function=None):
    """Creates a Java handler from an uploaded ZIP or JAR.

    :type zip_file_content: bytes
    :param zip_file_content: ZIP file bytes.
    :type handler: str
    :param handler: The lambda handler path.
    :type main_file: str
    :param main_file: Filepath to the uploaded ZIP or JAR file.

    :returns: function or flask.Response
    """
    if is_zip_file(zip_file_content):

        def execute(event, context):
            result = lambda_executors.EXECUTOR_LOCAL.execute_java_lambda(
                event, context, main_file=main_file, lambda_function=lambda_function
            )
            return result

        return execute
    raise ClientError(
        error_response(
            "Unable to extract Java Lambda handler - file is not a valid zip/jar file (%s, %s bytes)"
            % (main_file, len(zip_file_content or "")),
            400,
            error_type="ValidationError",
        )
    )


def set_archive_code(
    code: Dict, lambda_name_or_arn: str, zip_file_content: bytes = None
) -> Optional[str]:
    store = get_lambda_store_v1_for_arn(lambda_name_or_arn)
    # get metadata
    lambda_arn = func_arn(lambda_name_or_arn)
    lambda_details = store.lambdas[lambda_arn]
    is_local_mount = is_hot_reloading(code)

    if is_local_mount and config.LAMBDA_REMOTE_DOCKER:
        raise Exception("Please note that Lambda mounts cannot be used with LAMBDA_REMOTE_DOCKER=1")

    # Stop/remove any containers that this arn uses.
    LAMBDA_EXECUTOR.cleanup(lambda_arn)

    if is_local_mount:
        # Mount or use a local folder lambda executors can reference
        # WARNING: this means we're pointing lambda_cwd to a local path in the user's
        # file system! We must ensure that there is no data loss (i.e., we must *not* add
        # this folder to TMP_FILES or similar).
        lambda_details.cwd = code.get("S3Key")
        return code["S3Key"]

    # get file content
    zip_file_content = zip_file_content or get_zip_bytes(code)

    if not zip_file_content:
        return

    # Save the zip file to a temporary file that the lambda executors can reference
    code_sha_256 = base64.standard_b64encode(hashlib.sha256(zip_file_content).digest())
    latest_version = lambda_details.get_version(VERSION_LATEST)
    latest_version["CodeSize"] = len(zip_file_content)
    latest_version["CodeSha256"] = code_sha_256.decode("utf-8")
    zip_dir_name = f"function.zipfile.{short_uid()}"
    zip_dir = f"{config.dirs.tmp}/{zip_dir_name}"
    mkdir(zip_dir)
    tmp_file = f"{zip_dir}/{LAMBDA_ZIP_FILE_NAME}"
    save_file(tmp_file, zip_file_content)
    TMP_FILES.append(zip_dir)
    lambda_details.zip_dir = zip_dir
    lambda_details.cwd = f"{get_lambda_extraction_dir()}/{zip_dir_name}"
    mkdir(lambda_details.cwd)
    return zip_dir


def set_function_code(lambda_function: LambdaFunction):
    def _set_and_configure(*args, **kwargs):
        try:
            before = time.perf_counter()
            do_set_function_code(lambda_function)
            # initialize function code via plugins
            for plugin in lambda_executors.LambdaExecutorPlugin.get_plugins():
                plugin.init_function_code(lambda_function)
            lambda_function.state = "Active"
            LOG.debug(
                "Function code initialization for function '%s' complete. State => Active (in %.3fs)",
                lambda_function.name(),
                time.perf_counter() - before,
            )
        except Exception:
            lambda_function.state = "Failed"
            raise

    # unzipping can take some time - limit the execution time to avoid client/network timeout issues
    run_for_max_seconds(config.LAMBDA_CODE_EXTRACT_TIME, _set_and_configure)
    return {"FunctionName": lambda_function.name()}


def store_and_get_lambda_code_archive(
    lambda_function: LambdaFunction, zip_file_content: bytes = None
) -> Optional[Tuple[str, str, bytes]]:
    """Store the Lambda code referenced in the LambdaFunction details to disk as a zip file,
    and return the Lambda CWD, file name, and zip bytes content. May optionally return None
    in case this is a Lambda with the special bucket marker __local__, used for code mounting."""
    code_passed = lambda_function.code
    is_local_mount = is_hot_reloading(code_passed)
    lambda_zip_dir = lambda_function.zip_dir

    if code_passed:
        lambda_zip_dir = lambda_zip_dir or set_archive_code(code_passed, lambda_function.arn())
        if not zip_file_content and not is_local_mount:
            # Save the zip file to a temporary file that the lambda executors can reference
            zip_file_content = get_zip_bytes(code_passed)
    else:
        store = get_lambda_store_v1_for_arn(lambda_function.arn())
        lambda_details = store.lambdas[lambda_function.arn()]
        lambda_zip_dir = lambda_zip_dir or lambda_details.zip_dir

    if not lambda_zip_dir:
        return

    # construct archive name
    archive_file = os.path.join(lambda_zip_dir, LAMBDA_ZIP_FILE_NAME)

    if not zip_file_content:
        zip_file_content = load_file(archive_file, mode="rb")
    else:
        # override lambda archive with fresh code if we got an update
        save_file(archive_file, zip_file_content)
    # remove content from code attribute, if present
    lambda_function.code.pop("ZipFile", None)
    return lambda_zip_dir, archive_file, zip_file_content


def do_set_function_code(lambda_function: LambdaFunction):
    """Main function that creates the local zip archive for the given Lambda function, and
    optionally creates the handler function references (for LAMBDA_EXECUTOR=local)"""

    def generic_handler(*_):
        raise ClientError(
            (
                'Unable to find executor for Lambda function "%s". Note that '
                + "Node.js, Golang, and .Net Core Lambdas currently require LAMBDA_EXECUTOR=docker"
            )
            % lambda_name
        )

    lambda_name = lambda_function.name()
    arn = lambda_function.arn()
    runtime = get_lambda_runtime(lambda_function)
    lambda_environment = lambda_function.envvars
    handler_name = lambda_function.handler = lambda_function.handler or LAMBDA_DEFAULT_HANDLER
    code_passed = lambda_function.code
    is_local_mount = is_hot_reloading(code_passed)

    # cleanup any left-over Lambda executor instances
    LAMBDA_EXECUTOR.cleanup(arn)

    # get local Lambda code archive path
    _result = store_and_get_lambda_code_archive(lambda_function)
    if not _result:
        return
    lambda_zip_dir, archive_file, zip_file_content = _result
    lambda_cwd = lambda_function.cwd

    # Set the appropriate Lambda handler.
    lambda_handler = generic_handler
    is_java = lambda_executors.is_java_lambda(runtime)

    if is_java:
        # The Lambda executors for Docker subclass LambdaExecutorContainers, which
        # runs Lambda in Docker by passing all *.jar files in the function working
        # directory as part of the classpath. Obtain a Java handler function below.
        try:
            lambda_handler = get_java_handler(
                zip_file_content, archive_file, lambda_function=lambda_function
            )
        except Exception as e:
            # this can happen, e.g., for Lambda code mounted via __local__ -> ignore
            LOG.debug("Unable to determine Lambda Java handler: %s", e)

    if not is_local_mount:
        # Lambda code must be uploaded in Zip format
        if not is_zip_file(zip_file_content):
            raise ClientError(f"Uploaded Lambda code for runtime ({runtime}) is not in Zip format")
        # Unzip the Lambda archive contents

        if get_unzipped_size(archive_file) >= FUNCTION_MAX_UNZIPPED_SIZE:
            raise ClientError(
                error_response(
                    f"Unzipped size must be smaller than {FUNCTION_MAX_UNZIPPED_SIZE} bytes",
                    code=400,
                    error_type="InvalidParameterValueException",
                )
            )

        unzip(archive_file, lambda_cwd)
    # Obtain handler details for any non-Java Lambda function
    if not is_java:
        handler_file = get_handler_file_from_name(handler_name, runtime=runtime)
        main_file = f"{lambda_cwd}/{handler_file}"

        if CHECK_HANDLER_ON_CREATION and not os.path.exists(main_file):
            # Raise an error if (1) this is not a local mount lambda, or (2) we're
            # running Lambdas locally (not in Docker), or (3) we're using remote Docker.
            # -> We do *not* want to raise an error if we're using local mount in non-remote Docker
            if not is_local_mount or not use_docker() or config.LAMBDA_REMOTE_DOCKER:
                file_list = run(f'cd "{lambda_cwd}"; du -d 3 .')
                config_debug = f'Config for local mount, docker, remote: "{is_local_mount}", "{use_docker()}", "{config.LAMBDA_REMOTE_DOCKER}"'
                LOG.debug("Lambda archive content:\n%s", file_list)
                raise ClientError(
                    error_response(
                        f"Unable to find handler script ({main_file}) in Lambda archive. {config_debug}",
                        400,
                        error_type="ValidationError",
                    )
                )

        # TODO: init code below should be moved into LambdaExecutorLocal!

        if runtime.startswith("python") and not use_docker():
            try:
                # make sure the file is actually readable, then read contents
                ensure_readable(main_file)
                zip_file_content = load_file(main_file, mode="rb")
                # extract handler
                handler_function = get_handler_function_from_name(handler_name, runtime=runtime)

                def exec_local_python(event, context):
                    inner_handler = exec_lambda_code(
                        zip_file_content,
                        handler_function=handler_function,
                        lambda_cwd=lambda_cwd,
                        lambda_env=lambda_environment,
                    )
                    return inner_handler(event, context)

                lambda_handler = exec_local_python

            except Exception as e:
                raise ClientError("Unable to get handler function from lambda code: %s" % e)

        if runtime.startswith("node") and not use_docker():
            ensure_readable(main_file)

            def execute(event, context):
                result = lambda_executors.EXECUTOR_LOCAL.execute_javascript_lambda(
                    event, context, main_file=main_file, lambda_function=lambda_function
                )
                return result

            lambda_handler = execute

        if runtime.startswith("go1") and not use_docker():
            lambda_go_runtime_package.install()

            ensure_readable(main_file)

            def execute_go(event, context):
                result = lambda_executors.EXECUTOR_LOCAL.execute_go_lambda(
                    event, context, main_file=main_file, lambda_function=lambda_function
                )
                return result

            lambda_handler = execute_go

    if lambda_handler:
        lambda_executors.LambdaExecutorLocal.add_function_callable(lambda_function, lambda_handler)

    return lambda_handler


def do_list_functions():
    funcs = []
    store = get_lambda_store_v1()
    this_region = aws_stack.get_region()
    for f_arn, func in store.lambdas.items():
        if type(func) != LambdaFunction:
            continue

        # filter out functions of current region
        func_region = extract_region_from_arn(f_arn)
        if func_region != this_region:
            continue

        func_name = f_arn.split(":function:")[-1]
        arn = func_arn(func_name)
        lambda_function = store.lambdas.get(arn)
        if not lambda_function:
            # this can happen if we're accessing Lambdas from a different region (ARN mismatch)
            continue

        details = format_func_details(lambda_function)
        details["Tags"] = func.tags

        funcs.append(details)
    return funcs


def format_func_details(
    lambda_function: LambdaFunction, version: str = None, always_add_version=False
) -> Dict[str, Any]:
    version = version or VERSION_LATEST
    func_version = lambda_function.get_version(version)
    result = {
        "CodeSha256": func_version.get("CodeSha256"),
        "Role": lambda_function.role,
        "KMSKeyArn": lambda_function.kms_key_arn,
        "Version": version,
        "VpcConfig": lambda_function.vpc_config,
        "FunctionArn": lambda_function.arn(),
        "FunctionName": lambda_function.name(),
        "CodeSize": func_version.get("CodeSize"),
        "Handler": lambda_function.handler,
        "Runtime": lambda_function.runtime,
        "Timeout": lambda_function.timeout,
        "Description": lambda_function.description,
        "MemorySize": lambda_function.memory_size,
        "LastModified": format_timestamp(lambda_function.last_modified),
        "TracingConfig": lambda_function.tracing_config or {"Mode": "PassThrough"},
        "RevisionId": func_version.get("RevisionId"),
        "State": lambda_function.state,
        "LastUpdateStatus": "Successful",
        "PackageType": lambda_function.package_type,
        "ImageConfig": getattr(lambda_function, "image_config", None),
        "Architectures": lambda_function.architectures,
    }
    if lambda_function.dead_letter_config:
        result["DeadLetterConfig"] = lambda_function.dead_letter_config

    if lambda_function.envvars:
        result["Environment"] = {"Variables": lambda_function.envvars}
    arn_parts = result["FunctionArn"].split(":")
    if (always_add_version or version != VERSION_LATEST) and len(arn_parts) <= 7:
        result["FunctionArn"] += ":%s" % version
    return result


def forward_to_fallback_url(func_arn, data):
    """If LAMBDA_FALLBACK_URL is configured, forward the invocation of this non-existing
    Lambda to the configured URL."""
    if not config.LAMBDA_FALLBACK_URL:
        return

    lambda_name = arns.lambda_function_name(func_arn)
    if config.LAMBDA_FALLBACK_URL.startswith("dynamodb://"):
        table_name = urlparse(config.LAMBDA_FALLBACK_URL.replace("dynamodb://", "http://")).netloc
        dynamodb = connect_to().dynamodb
        item = {
            "id": {"S": short_uid()},
            "timestamp": {"N": str(now_utc())},
            "payload": {"S": data},
            "function_name": {"S": lambda_name},
        }
        resources.create_dynamodb_table(table_name, partition_key="id")
        dynamodb.put_item(TableName=table_name, Item=item)
        return ""
    if re.match(r"^https?://.+", config.LAMBDA_FALLBACK_URL):
        headers = {
            "lambda-function-name": lambda_name,
            "Content-Type": APPLICATION_JSON,
        }
        response = safe_requests.post(config.LAMBDA_FALLBACK_URL, data, headers=headers)
        content = response.content
        try:
            # parse the response into a dictionary to get details
            # like function error etc.
            content = json.loads(content)
        except Exception:
            pass

        return content
    raise ClientError("Unexpected value for LAMBDA_FALLBACK_URL: %s" % config.LAMBDA_FALLBACK_URL)


def get_lambda_policy(function, qualifier=None):
    iam_client = connect_to().iam
    policies = iam_client.list_policies(Scope="Local", MaxItems=500)["Policies"]
    docs = []
    for p in policies:
        # !TODO: Cache policy documents instead of running N+1 API calls here!
        versions = iam_client.list_policy_versions(PolicyArn=p["Arn"])["Versions"]
        default_version = [v for v in versions if v.get("IsDefaultVersion")]
        versions = default_version or versions
        doc = versions[0]["Document"]
        doc = doc if isinstance(doc, dict) else json.loads(doc)
        if not isinstance(doc["Statement"], list):
            doc["Statement"] = [doc["Statement"]]
        for stmt in doc["Statement"]:
            stmt["Principal"] = stmt.get("Principal") or {"AWS": get_aws_account_id()}
        doc["PolicyArn"] = p["Arn"]
        doc["PolicyName"] = p["PolicyName"]
        doc["Id"] = "default"
        docs.append(doc)

    # find policy by name
    policy_name = get_lambda_policy_name(arns.lambda_function_name(function), qualifier=qualifier)
    policy = [d for d in docs if d["PolicyName"] == policy_name]
    if policy:
        return policy[0]
    # find policy by target Resource in statement (TODO: check if this heuristic holds in the general case)
    res_qualifier = func_qualifier(function, qualifier)
    policy = [d for d in docs if d["Statement"][0]["Resource"] == res_qualifier]
    return (policy or [None])[0]


def get_lambda_policy_name(resource_name: str, qualifier: str = None) -> str:
    qualifier = qualifier or "latest"
    if ":function:" in resource_name:
        resource_name = function_name_from_arn(resource_name)
    return LAMBDA_POLICY_NAME_PATTERN.format(name=resource_name, qualifier=qualifier)


def lookup_function(function, region, request_url):
    result = {
        "Configuration": function,
        "Code": {"Location": "%s/code" % request_url},
        "Tags": function["Tags"],
    }
    lambda_details = region.lambdas.get(function["FunctionArn"])

    # patch for image lambdas (still missing RepositoryType and ResolvedImageUri)
    # please note that usage is still only available with a PRO license
    if lambda_details.package_type == "Image":
        result["Code"] = lambda_details.code
        result["Configuration"]["CodeSize"] = 0
        result["Configuration"].pop("Handler", None)
        result["Configuration"].pop("Layers", None)

    if lambda_details.concurrency is not None:
        result["Concurrency"] = lambda_details.concurrency
    return jsonify(result)


def not_found_error(ref=None, msg=None):
    if not msg:
        msg = "The resource you requested does not exist."
        if ref:
            msg = "%s not found: %s" % (
                "Function" if ":function:" in ref else "Resource",
                ref,
            )
    return error_response(msg, 404, error_type="ResourceNotFoundException")


def delete_lambda_function(function_name: str) -> Dict[None, None]:
    store = get_lambda_store_v1_for_arn(function_name)
    arn = func_arn(function_name)
    # Stop/remove any containers that this arn uses.
    LAMBDA_EXECUTOR.cleanup(arn)

    try:
        store.lambdas.pop(arn)
    except KeyError:
        raise ResourceNotFoundException(
            f"Unable to delete non-existing Lambda function {func_arn(function_name)}"
        )

    i = 0
    while i < len(store.event_source_mappings):
        mapping = store.event_source_mappings[i]
        if mapping["FunctionArn"] == arn:
            del store.event_source_mappings[i]
            i -= 1
        i += 1
    return {}


def get_lambda_url_config(api_id: str, region: str = None):
    store = get_lambda_store_v1(region=region)
    url_configs = store.url_configs.values()
    lambda_url_configs = [config for config in url_configs if config.get("CustomId") == api_id]
    return lambda_url_configs[0]


def event_for_lambda_url(api_id, path, data, headers, method) -> dict:
    raw_path = path.split("?")[0]
    raw_query_string = path.split("?")[1] if len(path.split("?")) > 1 else ""
    query_string_parameters = (
        {} if not raw_query_string else dict(urllib.parse.parse_qsl(raw_query_string))
    )

    now = datetime.utcnow()
    readable = timestamp(time=now, format=TIMESTAMP_READABLE_FORMAT)
    if not any(char in readable for char in ["+", "-"]):
        readable += "+0000"

    source_ip = headers.get("Remote-Addr", "")
    request_context = {
        "accountId": "anonymous",
        "apiId": api_id,
        "domainName": headers.get("Host", ""),
        "domainPrefix": api_id,
        "http": {
            "method": method,
            "path": raw_path,
            "protocol": "HTTP/1.1",
            "sourceIp": source_ip,
            "userAgent": headers.get("User-Agent", ""),
        },
        "requestId": long_uid(),
        "routeKey": "$default",
        "stage": "$default",
        "time": readable,
        "timeEpoch": mktime(ts=now, millis=True),
    }

    content_type = headers.get("Content-Type", "").lower()
    content_type_is_text = any(text_type in content_type for text_type in ["text", "json", "xml"])

    is_base64_encoded = not (data.isascii() and content_type_is_text) if data else False
    body = base64.b64encode(data).decode() if is_base64_encoded else data

    ignored_headers = ["connection", "x-localstack-tgt-api", "x-localstack-request-url"]
    event_headers = {k.lower(): v for k, v in headers.items() if k.lower() not in ignored_headers}

    event_headers.update(
        {
            "x-amzn-tls-cipher-suite": "ECDHE-RSA-AES128-GCM-SHA256",
            "x-amzn-tls-version": "TLSv1.2",
            "x-forwarded-proto": "http",
            "x-forwarded-for": source_ip,
            "x-forwarded-port": str(config.EDGE_PORT),
        }
    )

    event = {
        "version": "2.0",
        "routeKey": "$default",
        "rawPath": raw_path,
        "rawQueryString": raw_query_string,
        "headers": event_headers,
        "queryStringParameters": query_string_parameters,
        "requestContext": request_context,
        "body": body,
        "isBase64Encoded": is_base64_encoded,
    }

    if not data:
        event.pop("body")

    return event


def handle_lambda_url_invocation(
    request: Request, api_id: str, region: str, **url_params: Dict[str, str]
) -> HttpResponse:
    response = HttpResponse(headers={"Content-type": "application/json"})
    try:
        lambda_url_config = get_lambda_url_config(api_id, region)
    except IndexError as e:
        LOG.warning(f"Lambda URL ({api_id}) not found: {e}")
        response.set_json({"Message": None})
        response.status = "404"
        return response

    event = event_for_lambda_url(
        api_id, request.full_path, request.data, request.headers, request.method
    )

    try:
        result = process_lambda_url_invocation(lambda_url_config, event)
    except Exception as e:
        LOG.warning(f"Lambda URL ({api_id}) failed during execution: {e}")

        response.set_json({"Message": "lambda function failed during execution"})
        response.status = "403"
        return response

    response = lambda_result_to_response(result)
    return response


def json_or_eval(body: str):
    try:
        return json.loads(body)
    except JSONDecodeError:
        try:
            return ast.literal_eval(body)
        except Exception as e:
            LOG.error(f"Error parsing {body}", e)


def lambda_result_to_response(result: str):
    response = HttpResponse()

    # Set default headers
    response.headers.update(
        {
            "Content-Type": "application/json",
            "Connection": "keep-alive",
            "x-amzn-requestid": long_uid(),
            "x-amzn-trace-id": long_uid(),
        }
    )

    if isinstance(result, dict):
        parsed_result = result
    else:
        parsed_result = json_or_eval(result) or {}

    if isinstance(parsed_result.get("headers"), dict):
        response.headers.update(parsed_result.get("headers"))

    if "body" not in parsed_result:
        response.data = json.dumps(parsed_result)
    elif isinstance(parsed_result.get("body"), dict):
        response.data = json.dumps(parsed_result.get("body"))
    elif parsed_result.get("isBase64Encoded", False):
        body_bytes = to_bytes(to_str(parsed_result.get("body", "")))
        decoded_body_bytes = base64.b64decode(body_bytes)
        response.data = decoded_body_bytes
    else:
        response.data = parsed_result.get("body")

    return response


# ------------
# API METHODS
# ------------


@app.before_request
def before_request():
    # fix to enable chunked encoding, as this is used by some Lambda clients
    transfer_encoding = request.headers.get("Transfer-Encoding", "").lower()
    if transfer_encoding == "chunked":
        request.environ["wsgi.input_terminated"] = True


@app.route("%s/functions" % API_PATH_ROOT, methods=["POST"])
def create_function():
    """Create new function
    ---
    operationId: 'createFunction'
    parameters:
        - name: 'request'
          in: body
    """
    store = get_lambda_store_v1()
    arn = "n/a"
    try:
        if len(request.data) > FUNCTION_MAX_SIZE:
            return error_response(
                "Request size (%s) must be smaller than %s bytes for the CreateFunction operation"
                % (len(request.data), FUNCTION_MAX_SIZE),
                413,
                error_type="RequestEntityTooLargeException",
            )
        data = json.loads(to_str(request.data))
        lambda_name = data["FunctionName"]
        arn = func_arn(lambda_name)
        if arn in store.lambdas:
            return error_response(
                "Function already exist: %s" % lambda_name,
                409,
                error_type="ResourceConflictException",
            )
        lambda_function = LambdaFunction(arn)
        lambda_function.versions = {VERSION_LATEST: {"RevisionId": str(uuid.uuid4())}}
        lambda_function.vpc_config = data.get("VpcConfig", {})
        lambda_function.last_modified = datetime.utcnow()
        lambda_function.description = data.get("Description", "")
        lambda_function.handler = data.get("Handler")
        lambda_function.runtime = data.get("Runtime")
        try:
            lambda_function.envvars = data.get("Environment", {}).get("Variables", {})
        except InvalidEnvVars as e:
            return error_response(
                "Lambda was unable to configure your environment variables because the environment variables you have provided exceeded the 4KB limit. "
                f"String measured: {e}",
                400,
                error_type=INVALID_PARAMETER_VALUE_EXCEPTION,
            )
        lambda_function.tags = data.get("Tags", {})
        lambda_function.timeout = data.get("Timeout", LAMBDA_DEFAULT_TIMEOUT)
        lambda_function.role = data["Role"]
        lambda_function.kms_key_arn = data.get("KMSKeyArn")
        # Oddity in Lambda API (discovered when testing against Terraform test suite)
        # See https://github.com/hashicorp/terraform-provider-aws/issues/6366
        if not lambda_function.envvars:
            lambda_function.kms_key_arn = None
        lambda_function.memory_size = data.get("MemorySize")
        lambda_function.code_signing_config_arn = data.get("CodeSigningConfigArn")
        lambda_function.architectures = data.get("Architectures", ["x86_64"])
        lambda_function.code = data["Code"]
        lambda_function.package_type = data.get("PackageType") or "Zip"
        lambda_function.image_config = data.get("ImageConfig", {})
        lambda_function.tracing_config = data.get("TracingConfig", {})
        lambda_function.set_dead_letter_config(data)
        lambda_function.state = "Pending"
        store.lambdas[arn] = lambda_function
        result = set_function_code(lambda_function)
        if isinstance(result, Response):
            del store.lambdas[arn]
            return result
        # prepare result
        result.update(format_func_details(lambda_function))
        if data.get("Publish"):
            result["Version"] = publish_new_function_version(arn)["Version"]
        return jsonify(result or {})
    except Exception as e:
        store.lambdas.pop(arn, None)
        if isinstance(e, ClientError):
            return e.get_response()
        return error_response("Unknown error: %s %s" % (e, traceback.format_exc()))


@app.route("%s/functions/<function>" % API_PATH_ROOT, methods=["GET"])
def get_function(function):
    """Get details for a single function
    ---
    operationId: 'getFunction'
    parameters:
        - name: 'request'
          in: body
        - name: 'function'
          in: path
    """
    store = get_lambda_store_v1()
    funcs = do_list_functions()
    arn_regex = r".*%s($|:.+)" % function
    is_arn = ":" in function
    for func in funcs:
        if function == func["FunctionName"] or (
            is_arn and re.match(arn_regex, func["FunctionArn"])
        ):
            return lookup_function(func, store, request.url)
    return not_found_error(func_arn(function))


@app.route("%s/functions/" % API_PATH_ROOT, methods=["GET"])
def list_functions():
    """List functions
    ---
    operationId: 'listFunctions'
    parameters:
        - name: 'request'
          in: body
    """
    funcs = do_list_functions()
    result = {"Functions": funcs}
    return jsonify(result)


@app.route("%s/functions/<function>" % API_PATH_ROOT, methods=["DELETE"])
def delete_function(function):
    """Delete an existing function
    ---
    operationId: 'deleteFunction'
    parameters:
        - name: 'request'
          in: body
    """

    result = delete_lambda_function(function)
    return jsonify(result)


@app.route("%s/functions/<function>/code" % API_PATH_ROOT, methods=["PUT"])
def update_function_code(function):
    """Update the code of an existing function
    ---
    operationId: 'updateFunctionCode'
    parameters:
        - name: 'request'
          in: body
    """
    store = get_lambda_store_v1()
    arn = func_arn(function)
    lambda_function = store.lambdas.get(arn)
    if not lambda_function:
        return not_found_error("Function not found: %s" % arn)
    data = json.loads(to_str(request.data))
    lambda_function.code = data
    result = set_function_code(lambda_function)
    if isinstance(result, Response):
        return result
    if data.get("Architectures"):
        lambda_function.architectures = data["Architectures"]
    lambda_function.last_modified = datetime.utcnow()
    result.update(format_func_details(lambda_function))
    if data.get("Publish"):
        result["Version"] = publish_new_function_version(arn)["Version"]
    return jsonify(result or {})


@app.route("%s/functions/<function>/configuration" % API_PATH_ROOT, methods=["GET"])
def get_function_configuration(function):
    """Get the configuration of an existing function
    ---
    operationId: 'getFunctionConfiguration'
    parameters:
    """
    store = get_lambda_store_v1()
    arn = func_arn(function)
    lambda_details = store.lambdas.get(arn)
    if not lambda_details:
        return not_found_error(arn)
    result = format_func_details(lambda_details)
    return jsonify(result)


@app.route("%s/functions/<function>/configuration" % API_PATH_ROOT, methods=["PUT"])
def update_function_configuration(function):
    """Update the configuration of an existing function
    ---
    operationId: 'updateFunctionConfiguration'
    parameters:
        - name: 'request'
          in: body
    """
    store = get_lambda_store_v1()
    data = json.loads(to_str(request.data))
    arn = func_arn(function)

    # Stop/remove any containers that this arn uses.
    LAMBDA_EXECUTOR.cleanup(arn)

    lambda_details = store.lambdas.get(arn)
    if not lambda_details:
        return not_found_error('Unable to find Lambda function ARN "%s"' % arn)

    if data.get("Handler"):
        lambda_details.handler = data["Handler"]
    if data.get("Runtime"):
        lambda_details.runtime = data["Runtime"]
    lambda_details.set_dead_letter_config(data)
    env_vars = data.get("Environment", {}).get("Variables")
    if env_vars is not None:
        lambda_details.envvars = env_vars
    if data.get("Timeout"):
        lambda_details.timeout = data["Timeout"]
    if data.get("Role"):
        lambda_details.role = data["Role"]
    if data.get("MemorySize"):
        lambda_details.memory_size = data["MemorySize"]
    if data.get("Description"):
        lambda_details.description = data["Description"]
    if data.get("VpcConfig"):
        lambda_details.vpc_config = data["VpcConfig"]
    if data.get("KMSKeyArn"):
        lambda_details.kms_key_arn = data["KMSKeyArn"]
    if data.get("TracingConfig"):
        lambda_details.tracing_config = data["TracingConfig"]
    lambda_details.last_modified = datetime.utcnow()
    data.pop("Layers", None)
    result = data
    lambda_function = store.lambdas.get(arn)
    result.update(format_func_details(lambda_function))

    # initialize plugins
    for plugin in lambda_executors.LambdaExecutorPlugin.get_plugins():
        plugin.init_function_configuration(lambda_function)

    return jsonify(result)


def generate_policy_statement(sid, action, arn, sourcearn, principal, url_auth_type):

    statement = {
        "Sid": sid,
        "Effect": "Allow",
        "Action": action,
        "Resource": arn,
    }

    # Adds SourceArn only if SourceArn is present
    if sourcearn:
        condition = {"ArnLike": {"AWS:SourceArn": sourcearn}}
        statement["Condition"] = condition

    # Adds Principal only if Principal is present
    if principal:
        principal = "*" if principal == "*" else {"Service": principal}
        statement["Principal"] = principal

    if url_auth_type:
        statement["Condition"] = {"StringEquals": {"lambda:FunctionUrlAuthType": url_auth_type}}

    return statement


def generate_policy(sid, action, arn, sourcearn, principal, url_auth_type):
    new_statement = generate_policy_statement(sid, action, arn, sourcearn, principal, url_auth_type)
    policy = {
        "Version": IAM_POLICY_VERSION,
        "Id": "LambdaFuncAccess-%s" % sid,
        "Statement": [new_statement],
    }

    return policy


def cors_config_from_dict(cors: Dict):
    return {
        "Cors": {
            "AllowCredentials": cors.get("AllowCredentials", ["*"]),
            "AllowHeaders": cors.get("AllowHeaders", ["*"]),
            "AllowMethods": cors.get("AllowMethods", ["*"]),
            "AllowOrigins": cors.get("AllowOrigins", ["*"]),
            "ExposeHeaders": cors.get("ExposeHeaders", []),
            "MaxAge": cors.get("MaxAge", 0),
        }
    }


@app.route("%s/functions/<function>/policy" % API_PATH_ROOT, methods=["POST"])
def add_permission(function):
    arn = func_arn(function)
    qualifier = request.args.get("Qualifier")
    q_arn = func_qualifier(function, qualifier)
    result = add_permission_policy_statement(function, arn, q_arn, qualifier=qualifier)
    return result, 201


def correct_error_response_for_url_config(response):
    response_data = json.loads(response.data)
    response_data.update({"Message": response_data.get("message")})
    response.set_data(json.dumps(response_data))
    return response


@app.route("%s/functions/<function>/url" % API_PATH_ROOT_2, methods=["POST"])
def create_url_config(function):
    arn = func_arn(function)
    qualifier = request.args.get("Qualifier")
    q_arn = func_qualifier(function, qualifier)

    store = get_lambda_store_v1()
    function = store.lambdas.get(arn)
    if function is None:
        response = error_response("Function does not exist", 404, "ResourceNotFoundException")
        return correct_error_response_for_url_config(response)

    if qualifier and not function.qualifier_exists(qualifier=qualifier):
        return not_found_error()

    arn = q_arn or arn
    store = get_lambda_store_v1()
    if arn in store.url_configs:
        return error_response(
            f"Failed to create function url config for [functionArn = {arn}]. Error message:  FunctionUrlConfig exists for this Lambda function",
            409,
            "ResourceConflictException",
        )

    custom_id = md5(str(random()))
    region_name = aws_stack.get_region()
    host_definition = localstack_host(
        use_localhost_cloud=True, custom_port=config.EDGE_PORT_HTTP or config.EDGE_PORT
    )
    url = f"http://{custom_id}.lambda-url.{region_name}.{host_definition.host_and_port()}/"
    # TODO: HTTPS support

    data = json.loads(to_str(request.data))
    url_config = {
        "AuthType": data.get("AuthType"),
        "FunctionArn": arn,
        "FunctionUrl": url,
        "CreationTime": timestamp(format=TIMESTAMP_FORMAT_MICROS),
        "LastModifiedTime": timestamp(format=TIMESTAMP_FORMAT_MICROS),
        "CustomId": custom_id,
    }

    if "Cors" in data:
        url_config.update(cors_config_from_dict(data.get("Cors", {})))

    store.url_configs.update({arn: url_config})
    response = url_config.copy()
    response.pop("LastModifiedTime")
    response.pop("CustomId")
    return response, 201


@app.route("%s/functions/<function>/url" % API_PATH_ROOT_2, methods=["GET"])
def get_url_config(function):
    # if there's a qualifier it *must* be an alias
    qualifier = request.args.get("Qualifier")

    arn = func_arn(function)
    store = get_lambda_store_v1()

    # function doesn't exist
    fn = store.lambdas.get(arn)
    if not fn:
        return correct_error_response_for_url_config(
            error_response(
                "The resource you requested does not exist.",
                404,
                error_type="ResourceNotFoundException",
            )
        )

    # alias doesn't exist
    if qualifier and not fn.aliases.get(qualifier):
        return correct_error_response_for_url_config(
            error_response(
                "The resource you requested does not exist.",
                404,
                error_type="ResourceNotFoundException",
            )
        )

    # function url doesn't exit
    url_config = store.url_configs.get(arn)
    if not url_config:
        return correct_error_response_for_url_config(
            error_response(
                "The resource you requested does not exist.",
                404,
                error_type="ResourceNotFoundException",
            )
        )
    response = url_config.copy()
    response.pop("CustomId")
    return response


@app.route("%s/functions/<function>/url" % API_PATH_ROOT_2, methods=["PUT"])
def update_url_config(function):
    arn = func_arn(function)
    qualifier = request.args.get("Qualifier")
    q_arn = func_qualifier(function, qualifier)
    arn = q_arn or arn

    store = get_lambda_store_v1()
    prev_url_config = store.url_configs.get(arn)

    if prev_url_config is None:
        return not_found_error()

    data = json.loads(to_str(request.data))
    new_url_config = {
        "AuthType": data.get("AuthType"),
        "LastModifiedTime": timestamp(format=TIMESTAMP_FORMAT_MICROS),
    }
    if "Cors" in data:
        new_url_config.update(cors_config_from_dict(data.get("Cors", {})))

    prev_url_config.update(new_url_config)

    response = prev_url_config.copy()
    response.pop("CustomId")
    return response


@app.route("%s/functions/<function>/url" % API_PATH_ROOT_2, methods=["DELETE"])
def delete_url_config(function):
    arn = func_arn(function)
    qualifier = request.args.get("Qualifier")
    q_arn = func_qualifier(function, qualifier)
    arn = q_arn or arn

    store = get_lambda_store_v1()
    if arn not in store.url_configs:
        response = error_response("Function does not exist", 404, "ResourceNotFoundException")
        return response

    store.url_configs.pop(arn)
    return {}


def add_permission_policy_statement(
    resource_name, resource_arn, resource_arn_qualified, qualifier=None
):
    store = get_lambda_store_v1_for_arn(resource_arn)
    data = json.loads(to_str(request.data))
    iam_client = connect_to().iam
    sid = data.get("StatementId")
    action = data.get("Action")
    principal = data.get("Principal")
    sourcearn = data.get("SourceArn")
    function_url_auth_type = data.get("FunctionUrlAuthType")
    previous_policy = get_lambda_policy(resource_name, qualifier)

    if resource_arn not in store.lambdas:
        return not_found_error(resource_arn)

    if not re.match(r"lambda:[*]|lambda:[a-zA-Z]+|[*]", action):
        msg = (
            f'1 validation error detected: Value "{action}" at "action" failed to satisfy '
            "constraint: Member must satisfy regular expression pattern: "
            "(lambda:[*]|lambda:[a-zA-Z]+|[*])"
        )
        return error_response(msg, 400, error_type="ValidationException")

    new_policy = generate_policy(
        sid, action, resource_arn_qualified, sourcearn, principal, function_url_auth_type
    )
    new_statement = new_policy["Statement"][0]
    result = {"Statement": json.dumps(new_statement)}
    if previous_policy:
        statement_with_sid = next(
            (statement for statement in previous_policy["Statement"] if statement["Sid"] == sid),
            None,
        )
        if statement_with_sid and statement_with_sid == new_statement:
            LOG.debug(
                f"Policy Statement SID '{sid}' for Lambda '{resource_arn_qualified}' already exists"
            )
            return result
        if statement_with_sid:
            msg = (
                f"The statement id {sid} provided already exists. Please provide a new "
                "statement id, or remove the existing statement."
            )
            return error_response(msg, 400, error_type="ResourceConflictException")

        new_policy["Statement"].extend(previous_policy["Statement"])
        iam_client.delete_policy(PolicyArn=previous_policy["PolicyArn"])

    policy_name = get_lambda_policy_name(resource_name, qualifier=qualifier)
    LOG.debug('Creating IAM policy "%s" for Lambda resource %s', policy_name, resource_arn)

    iam_client.create_policy(
        PolicyName=policy_name,
        PolicyDocument=json.dumps(new_policy),
        Description='Policy for Lambda function "%s"' % resource_name,
    )

    return jsonify(result)


@app.route("%s/functions/<function>/policy/<statement>" % API_PATH_ROOT, methods=["DELETE"])
def remove_permission(function, statement):
    qualifier = request.args.get("Qualifier")
    iam_client = connect_to().iam
    policy = get_lambda_policy(function, qualifier=qualifier)
    if not policy:
        return not_found_error('Unable to find policy for Lambda function "%s"' % function)

    statement_index = next(
        (i for i, item in enumerate(policy["Statement"]) if item["Sid"] == statement), None
    )
    if statement_index is None:
        return not_found_error(f"Statement {statement} is not found in resource policy.")
    iam_client.delete_policy(PolicyArn=policy["PolicyArn"])

    policy["Statement"].pop(statement_index)
    description = policy.get("Description")
    policy_name = policy.get("PolicyName")
    del policy["PolicyName"]
    del policy["PolicyArn"]
    if len(policy["Statement"]) > 0 and description:
        iam_client.create_policy(
            PolicyName=policy_name,
            PolicyDocument=json.dumps(policy),
            Description=description,
        )
    elif len(policy["Statement"]) > 0:
        iam_client.create_policy(PolicyName=policy_name, PolicyDocument=json.dumps(policy))

    result = {
        "FunctionName": function,
        "Qualifier": qualifier,
        "StatementId": statement,
    }
    return jsonify(result)


@app.route("%s/functions/<function>/policy" % API_PATH_ROOT, methods=["GET"])
def get_policy(function):
    qualifier = request.args.get("Qualifier")
    policy = get_lambda_policy(function, qualifier)
    if not policy:
        return not_found_error("The resource you requested does not exist.")
    return jsonify({"Policy": json.dumps(policy), "RevisionId": "test1234"})


@app.route("%s/functions/<function>/invocations" % API_PATH_ROOT, methods=["POST"])
def invoke_function(function):
    """Invoke an existing function
    ---
    operationId: 'invokeFunction'
    parameters:
        - name: 'request'
          in: body
    """
    # function here can either be an arn or a function name
    arn = func_arn(function)

    # ARN can also contain a qualifier, extract it from there if so
    m = re.match("(arn:aws:lambda:.*:.*:function:[a-zA-Z0-9-_]+)(:.*)?", arn)
    if m and m.group(2):
        qualifier = m.group(2)[1:]
        arn = m.group(1)
    else:
        qualifier = request.args.get("Qualifier")
    data = request.get_data() or ""
    if data:
        try:
            data = to_str(data)
            data = json.loads(data)
        except Exception:
            try:
                # try to read chunked content
                data = json.loads(parse_chunked_data(data))
            except Exception:
                return error_response(
                    "The payload is not JSON: %s" % data,
                    415,
                    error_type="UnsupportedMediaTypeException",
                )

    # Default invocation type is RequestResponse
    invocation_type = request.headers.get("X-Amz-Invocation-Type", "RequestResponse")
    log_type = request.headers.get("X-Amz-Log-Type")

    def _create_response(invocation_result, status_code=200, headers=None):
        """Create the final response for the given invocation result."""
        if headers is None:
            headers = {}
        if not isinstance(invocation_result, InvocationResult):
            invocation_result = InvocationResult(invocation_result)
        result = invocation_result.result
        log_output = invocation_result.log_output
        details = {"StatusCode": status_code, "Payload": result, "Headers": headers}
        if isinstance(result, Response):
            details["Payload"] = to_str(result.data)
            if result.status_code >= 400:
                details["FunctionError"] = "Unhandled"
        if isinstance(result, (str, bytes)):
            try:
                result = json.loads(to_str(result))
            except Exception:
                pass
        if isinstance(result, dict):
            for key in ("StatusCode", "Payload", "FunctionError"):
                if result.get(key):
                    details[key] = result[key]
        # Try to parse payload as JSON
        was_json = False
        payload = details["Payload"]
        if payload and isinstance(payload, POSSIBLE_JSON_TYPES) and payload[0] in JSON_START_CHARS:
            try:
                details["Payload"] = json.loads(details["Payload"])
                was_json = True
            except Exception:
                pass
        # Set error headers
        if details.get("FunctionError"):
            details["Headers"]["X-Amz-Function-Error"] = str(details["FunctionError"])
        # LogResult contains the last 4KB (~4k characters) of log outputs
        logs = log_output[-4000:] if log_type == "Tail" else ""
        details["Headers"]["X-Amz-Log-Result"] = to_str(base64.b64encode(to_bytes(logs)))
        details["Headers"]["X-Amz-Executed-Version"] = str(qualifier or VERSION_LATEST)
        # Construct response object
        response_obj = details["Payload"]
        if was_json or isinstance(response_obj, JSON_START_TYPES):
            response_obj = json_safe(response_obj)
            # Content-type header is not required since jsonify automatically adds it
            response_obj = jsonify(response_obj)
        else:
            response_obj = str(response_obj)
            details["Headers"]["Content-Type"] = "text/plain"
        return response_obj, details["StatusCode"], details["Headers"]

    # check if this lambda function exists
    not_found = None
    store = get_lambda_store_v1()
    if arn not in store.lambdas:
        not_found = not_found_error(arn)
    elif qualifier and not store.lambdas.get(arn).qualifier_exists(qualifier):
        not_found = not_found_error("{0}:{1}".format(arn, qualifier))

    # remove this block when AWS updates the stepfunctions image to support aws-sdk invocations
    if not_found and "localstack-internal-awssdk" in arn:
        # init aws-sdk stepfunctions handler
        from localstack.services.stepfunctions.packages import stepfunctions_local_package

        code = load_file(
            os.path.join(
                stepfunctions_local_package.get_installed_dir(),
                "localstack-internal-awssdk",
                "awssdk.zip",
            ),
            mode="rb",
        )
        lambda_client = connect_to().lambda_
        lambda_client.create_function(
            FunctionName="localstack-internal-awssdk",
            Runtime=LAMBDA_RUNTIME_NODEJS14X,
            Handler="index.handler",
            Code={"ZipFile": code},
            Role=LAMBDA_TEST_ROLE.format(account_id=get_aws_account_id()),
            Timeout=30,
        )
        not_found = None

    if not_found:
        try:
            forward_result = forward_to_fallback_url(arn, json.dumps(data))
            if forward_result is not None:
                return _create_response(forward_result)
        except Exception as e:
            LOG.debug('Unable to forward Lambda invocation to fallback URL: "%s" - %s', data, e)
        return not_found

    if invocation_type == "RequestResponse":
        context = {"client_context": request.headers.get("X-Amz-Client-Context")}

        time_before = time.perf_counter()
        try:
            result = run_lambda(
                func_arn=arn,
                event=data,
                context=context,
                asynchronous=False,
                version=qualifier,
            )
        except ClientError as e:
            return e.get_response()
        finally:
            LOG.debug(
                "Lambda invocation duration: %0.2fms", (time.perf_counter() - time_before) * 1000
            )
        return _create_response(result)
    elif invocation_type == "Event":
        try:
            run_lambda(func_arn=arn, event=data, context={}, asynchronous=True, version=qualifier)
        except ClientError as e:
            return e.get_response()
        return _create_response("", status_code=202)
    elif invocation_type == "DryRun":
        # Assume the dry run always passes.
        return _create_response("", status_code=204)
    return error_response(
        "Invocation type not one of: RequestResponse, Event or DryRun",
        code=400,
        error_type="InvalidParameterValueException",
    )


@app.route("%s/event-source-mappings" % API_PATH_ROOT, methods=["GET"])
def get_event_source_mappings():
    """List event source mappings
    ---
    operationId: 'listEventSourceMappings'
    """
    store = get_lambda_store_v1()
    event_source_arn = request.args.get("EventSourceArn")
    function_name = request.args.get("FunctionName")

    mappings = store.event_source_mappings
    if event_source_arn:
        mappings = [m for m in mappings if event_source_arn == m.get("EventSourceArn")]
    if function_name:
        function_arn = func_arn(function_name)
        mappings = [m for m in mappings if function_arn == m.get("FunctionArn")]

    response = {"EventSourceMappings": mappings}
    return jsonify(response)


@app.route("%s/event-source-mappings/<mapping_uuid>" % API_PATH_ROOT, methods=["GET"])
def get_event_source_mapping(mapping_uuid):
    """Get an existing event source mapping
    ---
    operationId: 'getEventSourceMapping'
    parameters:
        - name: 'request'
          in: body
    """
    store = get_lambda_store_v1()
    mappings = store.event_source_mappings
    mappings = [m for m in mappings if mapping_uuid == m.get("UUID")]

    if len(mappings) == 0:
        return not_found_error()
    return jsonify(mappings[0])


@app.route("%s/event-source-mappings" % API_PATH_ROOT, methods=["POST"])
def create_event_source_mapping():
    """Create new event source mapping
    ---
    operationId: 'createEventSourceMapping'
    parameters:
        - name: 'request'
          in: body
    """
    data = json.loads(to_str(request.data))
    try:
        mapping = add_event_source(data)
        return jsonify(mapping)
    except ValueError as error:
        error_type, message = error.args
        return error_response(message, code=400, error_type=error_type)


@app.route("%s/event-source-mappings/<mapping_uuid>" % API_PATH_ROOT, methods=["PUT"])
def update_event_source_mapping(mapping_uuid):
    """Update an existing event source mapping
    ---
    operationId: 'updateEventSourceMapping'
    parameters:
        - name: 'request'
          in: body
    """
    data = json.loads(to_str(request.data))
    if not mapping_uuid:
        return jsonify({})

    try:
        mapping = update_event_source(mapping_uuid, data)
        return jsonify(mapping)
    except ValueError as error:
        error_type, message = error.args
        return error_response(message, code=400, error_type=error_type)


@app.route("%s/event-source-mappings/<mapping_uuid>" % API_PATH_ROOT, methods=["DELETE"])
def delete_event_source_mapping(mapping_uuid):
    """Delete an event source mapping
    ---
    operationId: 'deleteEventSourceMapping'
    """
    if not mapping_uuid:
        return jsonify({})

    mapping = delete_event_source(mapping_uuid)
    return jsonify(mapping)


@app.route("%s/functions/<function>/versions" % API_PATH_ROOT, methods=["POST"])
def publish_version(function):
    store = get_lambda_store_v1()
    arn = func_arn(function)
    if arn not in store.lambdas:
        return not_found_error(arn)
    return jsonify(publish_new_function_version(arn))


@app.route("%s/functions/<function>/versions" % API_PATH_ROOT, methods=["GET"])
def list_versions(function):
    store = get_lambda_store_v1()
    arn = func_arn(function)
    if arn not in store.lambdas:
        return not_found_error(arn)
    return jsonify({"Versions": do_list_versions(arn)})


@app.route("%s/functions/<function>/aliases" % API_PATH_ROOT, methods=["POST"])
def create_alias(function):
    store = get_lambda_store_v1()
    arn = func_arn(function)
    if arn not in store.lambdas:
        return not_found_error(arn)
    data = json.loads(request.data)
    alias = data.get("Name")
    if alias in store.lambdas.get(arn).aliases:
        return error_response(
            "Alias already exists: %s" % arn + ":" + alias,
            404,
            error_type="ResourceConflictException",
        )
    version = data.get("FunctionVersion")
    description = data.get("Description")
    return jsonify(do_update_alias(arn, alias, version, description))


@app.route("%s/functions/<function>/aliases/<name>" % API_PATH_ROOT, methods=["PUT"])
def update_alias(function, name):
    store = get_lambda_store_v1()
    arn = func_arn(function)
    if arn not in store.lambdas:
        return not_found_error(arn)
    if name not in store.lambdas.get(arn).aliases:
        return not_found_error(msg="Alias not found: %s:%s" % (arn, name))
    current_alias = store.lambdas.get(arn).aliases.get(name)
    data = json.loads(request.data)
    version = data.get("FunctionVersion") or current_alias.get("FunctionVersion")
    description = data.get("Description") or current_alias.get("Description")
    return jsonify(do_update_alias(arn, name, version, description))


@app.route("%s/functions/<function>/aliases/<name>" % API_PATH_ROOT, methods=["GET"])
def get_alias(function, name):
    store = get_lambda_store_v1()
    arn = func_arn(function)
    if arn not in store.lambdas:
        return not_found_error(arn)
    if name not in store.lambdas.get(arn).aliases:
        return not_found_error(msg="Alias not found: %s:%s" % (arn, name))
    return jsonify(store.lambdas.get(arn).aliases.get(name))


@app.route("%s/functions/<function>/aliases" % API_PATH_ROOT, methods=["GET"])
def list_aliases(function):
    store = get_lambda_store_v1()
    arn = func_arn(function)
    if arn not in store.lambdas:
        return not_found_error(arn)
    return jsonify(
        {"Aliases": sorted(store.lambdas.get(arn).aliases.values(), key=lambda x: x["Name"])}
    )


@app.route("%s/functions/<function>/aliases/<name>" % API_PATH_ROOT, methods=["DELETE"])
def delete_alias(function, name):
    store = get_lambda_store_v1()
    arn = func_arn(function)
    if arn not in store.lambdas:
        return not_found_error(arn)
    lambda_details = store.lambdas.get(arn)
    if name not in lambda_details.aliases:
        return not_found_error(msg="Alias not found: %s:%s" % (arn, name))
    lambda_details.aliases.pop(name)
    return jsonify({})


@app.route("/<version>/functions/<function>/concurrency", methods=["GET", "PUT", "DELETE"])
def function_concurrency(version, function):
    store = get_lambda_store_v1()
    # the version for put_concurrency != API_PATH_ROOT, at the time of this
    # writing it's: /2017-10-31 for this endpoint
    # https://docs.aws.amazon.com/lambda/latest/dg/API_PutFunctionConcurrency.html
    arn = func_arn(function)
    lambda_details = store.lambdas.get(arn)
    if not lambda_details:
        return not_found_error(arn)
    if request.method == "GET":
        data = lambda_details.concurrency
    if request.method == "PUT":
        data = json.loads(request.data)
        lambda_details.concurrency = data
    if request.method == "DELETE":
        lambda_details.concurrency = None
        return Response("", status=204)
    return jsonify(data)


@app.route("/<version>/tags/<arn>", methods=["GET"])
def list_tags(version, arn):
    store = get_lambda_store_v1()
    lambda_function = store.lambdas.get(arn)
    if not lambda_function:
        return not_found_error(arn)
    result = {"Tags": lambda_function.tags}
    return jsonify(result)


@app.route("/<version>/tags/<arn>", methods=["POST"])
def tag_resource(version, arn):
    store = get_lambda_store_v1()
    data = json.loads(request.data)
    tags = data.get("Tags", {})
    if tags:
        lambda_function = store.lambdas.get(arn)
        if not lambda_function:
            return not_found_error(arn)
        if lambda_function:
            lambda_function.tags.update(tags)
    return jsonify({})


@app.route("/<version>/tags/<arn>", methods=["DELETE"])
def untag_resource(version, arn):
    store = get_lambda_store_v1()
    tag_keys = request.args.getlist("tagKeys")
    lambda_function = store.lambdas.get(arn)
    if not lambda_function:
        return not_found_error(arn)
    for tag_key in tag_keys:
        lambda_function.tags.pop(tag_key, None)
    return jsonify({})


@app.route("/2019-09-25/functions/<function>/event-invoke-config", methods=["PUT", "POST"])
def put_function_event_invoke_config(function):
    # TODO: resouce validation required to check if resource exists
    """Add/Updates the configuration for asynchronous invocation for a function
    ---
    operationId: PutFunctionEventInvokeConfig | UpdateFunctionEventInvokeConfig
    parameters:
        - name: 'function'
          in: path
        - name: 'qualifier'
          in: path
        - name: 'request'
          in: body
    """
    store = get_lambda_store_v1()
    data = json.loads(to_str(request.data))
    function_arn = func_arn(function)
    lambda_obj = store.lambdas.get(function_arn)
    if not lambda_obj:
        return not_found_error("Unable to find Lambda ARN: %s" % function_arn)

    if request.method == "PUT":
        response = lambda_obj.clear_function_event_invoke_config()
    response = lambda_obj.put_function_event_invoke_config(data)

    return jsonify(
        {
            "LastModified": response.last_modified.strftime(DATE_FORMAT),
            "FunctionArn": str(function_arn),
            "MaximumRetryAttempts": response.max_retry_attempts,
            "MaximumEventAgeInSeconds": response.max_event_age,
            "DestinationConfig": {
                "OnSuccess": {"Destination": str(response.on_successful_invocation)},
                "OnFailure": {"Destination": str(response.on_failed_invocation)},
            },
        }
    )


@app.route("/2019-09-25/functions/<function>/event-invoke-config", methods=["GET"])
def get_function_event_invoke_config(function):
    """Retrieves the configuration for asynchronous invocation for a function
    ---
    operationId: GetFunctionEventInvokeConfig
    parameters:
        - name: 'function'
          in: path
        - name: 'qualifier'
          in: path
        - name: 'request'
          in: body
    """
    store = get_lambda_store_v1()
    try:
        function_arn = func_arn(function)
        lambda_obj = store.lambdas[function_arn]
    except Exception:
        return not_found_error("Unable to find Lambda function ARN %s" % function_arn)

    response = lambda_obj.get_function_event_invoke_config()
    if not response:
        msg = "The function %s doesn't have an EventInvokeConfig" % function_arn
        return not_found_error(msg)
    return jsonify(response)


@app.route("/2019-09-25/functions/<function>/event-invoke-config", methods=["DELETE"])
def delete_function_event_invoke_config(function):
    store = get_lambda_store_v1()
    try:
        function_arn = func_arn(function)
        if function_arn not in store.lambdas:
            msg = f"Function not found: {function_arn}"
            return not_found_error(msg)
        lambda_obj = store.lambdas[function_arn]
    except Exception as e:
        return error_response(str(e), 400)

    lambda_obj.clear_function_event_invoke_config()
    return Response("", status=204)


@app.route("/2020-06-30/functions/<function>/code-signing-config", methods=["GET"])
def get_function_code_signing_config(function):
    store = get_lambda_store_v1()
    function_arn = func_arn(function)
    if function_arn not in store.lambdas:
        msg = "Function not found: %s" % (function_arn)
        return not_found_error(msg)
    lambda_obj = store.lambdas[function_arn]

    if not lambda_obj.code_signing_config_arn:
        arn = None
        function = None
    else:
        arn = lambda_obj.code_signing_config_arn

    result = {"CodeSigningConfigArn": arn, "FunctionName": function}
    return Response(json.dumps(result), status=200)


@app.route("/2020-06-30/functions/<function>/code-signing-config", methods=["PUT"])
def put_function_code_signing_config(function):
    store = get_lambda_store_v1()
    data = json.loads(request.data)

    arn = data.get("CodeSigningConfigArn")
    if arn not in store.code_signing_configs:
        msg = """The code signing configuration cannot be found.
        Check that the provided configuration is not deleted: %s.""" % (
            arn
        )
        return error_response(msg, 404, error_type="CodeSigningConfigNotFoundException")

    function_arn = func_arn(function)
    if function_arn not in store.lambdas:
        msg = "Function not found: %s" % (function_arn)
        return not_found_error(msg)
    lambda_obj = store.lambdas[function_arn]

    if data.get("CodeSigningConfigArn"):
        lambda_obj.code_signing_config_arn = arn

    result = {"CodeSigningConfigArn": arn, "FunctionName": function}

    return Response(json.dumps(result), status=200)


@app.route("/2020-06-30/functions/<function>/code-signing-config", methods=["DELETE"])
def delete_function_code_signing_config(function):
    store = get_lambda_store_v1()
    function_arn = func_arn(function)
    if function_arn not in store.lambdas:
        msg = "Function not found: %s" % (function_arn)
        return not_found_error(msg)

    lambda_obj = store.lambdas[function_arn]

    lambda_obj.code_signing_config_arn = None

    return Response("", status=204)


@app.route("/2020-04-22/code-signing-configs/", methods=["POST"])
def create_code_signing_config():
    store = get_lambda_store_v1()
    data = json.loads(request.data)
    signing_profile_version_arns = data.get("AllowedPublishers").get("SigningProfileVersionArns")

    code_signing_id = "csc-%s" % long_uid().replace("-", "")[0:17]
    arn = arns.code_signing_arn(code_signing_id)

    store.code_signing_configs[arn] = CodeSigningConfig(
        arn, code_signing_id, signing_profile_version_arns
    )

    code_signing_obj = store.code_signing_configs[arn]

    if data.get("Description"):
        code_signing_obj.description = data["Description"]
    if data.get("CodeSigningPolicies", {}).get("UntrustedArtifactOnDeployment"):
        code_signing_obj.untrusted_artifact_on_deployment = data["CodeSigningPolicies"][
            "UntrustedArtifactOnDeployment"
        ]
    code_signing_obj.last_modified = format_timestamp()

    result = {
        "CodeSigningConfig": {
            "AllowedPublishers": {
                "SigningProfileVersionArns": code_signing_obj.signing_profile_version_arns
            },
            "CodeSigningConfigArn": code_signing_obj.arn,
            "CodeSigningConfigId": code_signing_obj.id,
            "CodeSigningPolicies": {
                "UntrustedArtifactOnDeployment": code_signing_obj.untrusted_artifact_on_deployment
            },
            "Description": code_signing_obj.description,
            "LastModified": code_signing_obj.last_modified,
        }
    }

    return Response(json.dumps(result), status=201)


@app.route("/2020-04-22/code-signing-configs/<arn>", methods=["GET"])
def get_code_signing_config(arn):
    store = get_lambda_store_v1()
    try:
        code_signing_obj = store.code_signing_configs[arn]
    except KeyError:
        msg = "The Lambda code signing configuration %s can not be found." % arn
        return not_found_error(msg)

    result = {
        "CodeSigningConfig": {
            "AllowedPublishers": {
                "SigningProfileVersionArns": code_signing_obj.signing_profile_version_arns
            },
            "CodeSigningConfigArn": code_signing_obj.arn,
            "CodeSigningConfigId": code_signing_obj.id,
            "CodeSigningPolicies": {
                "UntrustedArtifactOnDeployment": code_signing_obj.untrusted_artifact_on_deployment
            },
            "Description": code_signing_obj.description,
            "LastModified": code_signing_obj.last_modified,
        }
    }

    return Response(json.dumps(result), status=200)


@app.route("/2020-04-22/code-signing-configs/<arn>", methods=["DELETE"])
def delete_code_signing_config(arn):
    store = get_lambda_store_v1()
    try:
        store.code_signing_configs.pop(arn)
    except KeyError:
        msg = "The Lambda code signing configuration %s can not be found." % (arn)
        return not_found_error(msg)

    return Response("", status=204)


@app.route("/2020-04-22/code-signing-configs/<arn>", methods=["PUT"])
def update_code_signing_config(arn):
    store = get_lambda_store_v1()
    try:
        code_signing_obj = store.code_signing_configs[arn]
    except KeyError:
        msg = "The Lambda code signing configuration %s can not be found." % (arn)
        return not_found_error(msg)

    data = json.loads(request.data)
    is_updated = False
    if data.get("Description"):
        code_signing_obj.description = data["Description"]
        is_updated = True
    if data.get("AllowedPublishers", {}).get("SigningProfileVersionArns"):
        code_signing_obj.signing_profile_version_arns = data["AllowedPublishers"][
            "SigningProfileVersionArns"
        ]
        is_updated = True
    if data.get("CodeSigningPolicies", {}).get("UntrustedArtifactOnDeployment"):
        code_signing_obj.untrusted_artifact_on_deployment = data["CodeSigningPolicies"][
            "UntrustedArtifactOnDeployment"
        ]
        is_updated = True

    if is_updated:
        code_signing_obj.last_modified = format_timestamp()

    result = {
        "CodeSigningConfig": {
            "AllowedPublishers": {
                "SigningProfileVersionArns": code_signing_obj.signing_profile_version_arns
            },
            "CodeSigningConfigArn": code_signing_obj.arn,
            "CodeSigningConfigId": code_signing_obj.id,
            "CodeSigningPolicies": {
                "UntrustedArtifactOnDeployment": code_signing_obj.untrusted_artifact_on_deployment
            },
            "Description": code_signing_obj.description,
            "LastModified": code_signing_obj.last_modified,
        }
    }

    return Response(json.dumps(result), status=200)


def validate_lambda_config():
    """Validates important config variables necessary for flawless lambda execution"""
    if (
        config.LAMBDA_DOCKER_NETWORK
        and config.is_in_docker
        and config.LAMBDA_DOCKER_NETWORK
        not in DOCKER_CLIENT.get_networks(get_main_container_name())
    ):
        LOG.warning(
            "Your specified LAMBDA_DOCKER_NETWORK '%s' is not connected to the main LocalStack container '%s'. "
            "Lambda functionality might be severely limited.",
            config.LAMBDA_DOCKER_NETWORK,
            get_main_container_name(),
        )


def serve(port):
    try:
        # initialize the Lambda executor
        LAMBDA_EXECUTOR.startup()
        # print warnings for potentially incorrect config options
        validate_lambda_config()

        _serve_flask_app(app=app, port=port)
    except Exception:
        LOG.exception("Error while starting up lambda service")
        raise


def _serve_flask_app(app, port, host=None, cors=True, asynchronous=False):
    if cors:
        CORS(app)
    if not config.DEBUG:
        logging.getLogger("werkzeug").setLevel(logging.ERROR)
    if not host:
        host = "0.0.0.0"
    ssl_context = None
    if not config.FORWARD_EDGE_INMEM and config.USE_SSL:
        _, cert_file_name, key_file_name = create_ssl_cert(serial_number=port)
        ssl_context = cert_file_name, key_file_name
    app.config["ENV"] = "development"

    def noecho(*args, **kwargs):
        pass

    try:
        import click

        click.echo = noecho
    except Exception:
        pass

    def _run(*_):
        app.run(port=int(port), threaded=True, host=host, ssl_context=ssl_context)
        return app

    if asynchronous:
        return start_thread(_run, name="flaskapp")
    return _run()


# Config listener
def on_config_change(config_key: str, config_newvalue: str) -> None:
    global LAMBDA_EXECUTOR
    if config_key != "LAMBDA_EXECUTOR":
        return
    LOG.debug(
        "Received config event for lambda executor - Key: '{}', Value: {}".format(
            config_key, config_newvalue
        )
    )
    LAMBDA_EXECUTOR.cleanup()
    LAMBDA_EXECUTOR = lambda_executors.AVAILABLE_EXECUTORS.get(
        get_executor_mode(), lambda_executors.DEFAULT_EXECUTOR
    )
    LAMBDA_EXECUTOR.startup()


def register_config_listener():
    from localstack.utils import config_listener

    config_listener.CONFIG_LISTENERS.append(on_config_change)


register_config_listener()
