import glob
import importlib
import io
import json
import os
import re
import shutil
import tempfile
import time
from contextlib import contextmanager
from typing import Any, Callable, Dict, List, Optional, Tuple

from localstack.aws.connect import connect_externally_to, connect_to
from localstack.testing.aws.util import is_aws_cloud
from localstack.utils.aws import arns
from localstack.utils.aws import resources as resource_utils

try:
    from typing import Literal
except ImportError:
    from typing_extensions import Literal

import boto3
import requests

from localstack import config
from localstack.aws.accounts import get_aws_account_id
from localstack.constants import (
    LOCALHOST_HOSTNAME,
    LOCALSTACK_ROOT_FOLDER,
    LOCALSTACK_VENV_FOLDER,
    TEST_AWS_REGION_NAME,
)
from localstack.services.lambda_.lambda_api import LAMBDA_TEST_ROLE
from localstack.services.lambda_.lambda_utils import (
    LAMBDA_DEFAULT_HANDLER,
    LAMBDA_DEFAULT_RUNTIME,
    LAMBDA_DEFAULT_STARTING_POSITION,
    get_handler_file_from_name,
)
from localstack.utils.archives import create_zip_file_cli, create_zip_file_python
from localstack.utils.aws import aws_stack
from localstack.utils.collections import ensure_list
from localstack.utils.files import (
    TMP_FILES,
    chmod_r,
    cp_r,
    is_empty_dir,
    load_file,
    mkdir,
    rm_rf,
    save_file,
)
from localstack.utils.net import get_free_tcp_port, is_port_open
from localstack.utils.platform import is_debian
from localstack.utils.strings import short_uid, to_str
from localstack.utils.sync import poll_condition
from localstack.utils.threads import FuncThread

ARCHIVE_DIR_PREFIX = "lambda.archive."
DEFAULT_GET_LOG_EVENTS_DELAY = 3
LAMBDA_TIMEOUT_SEC = 30
LAMBDA_ASSETS_BUCKET_NAME = "ls-test-lambda-assets-bucket"
MAX_LAMBDA_ARCHIVE_UPLOAD_SIZE = 50_000_000


def is_local_test_mode():
    return config.is_local_test_mode()


def create_lambda_archive(
    script: str,
    get_content: bool = False,
    libs: List[str] = None,
    runtime: str = None,
    file_name: str = None,
    exclude_func: Callable[[str], bool] = None,
):
    """Utility method to create a Lambda function archive"""
    if libs is None:
        libs = []
    runtime = runtime or LAMBDA_DEFAULT_RUNTIME

    with tempfile.TemporaryDirectory(prefix=ARCHIVE_DIR_PREFIX) as tmp_dir:
        file_name = file_name or get_handler_file_from_name(LAMBDA_DEFAULT_HANDLER, runtime=runtime)
        script_file = os.path.join(tmp_dir, file_name)
        if os.path.sep in script_file:
            mkdir(os.path.dirname(script_file))
            # create __init__.py files along the path to allow Python imports
            path = file_name.split(os.path.sep)
            for i in range(1, len(path)):
                save_file(os.path.join(tmp_dir, *(path[:i] + ["__init__.py"])), "")
        save_file(script_file, script)
        chmod_r(script_file, 0o777)
        # copy libs
        for lib in libs:
            paths = [lib, "%s.py" % lib]
            try:
                module = importlib.import_module(lib)
                paths.append(module.__file__)
            except Exception:
                pass
            target_dir = tmp_dir
            root_folder = os.path.join(LOCALSTACK_VENV_FOLDER, "lib/python*/site-packages")
            if lib == "localstack":
                paths = ["localstack/*.py", "localstack/utils"]
                root_folder = LOCALSTACK_ROOT_FOLDER
                target_dir = os.path.join(tmp_dir, lib)
                mkdir(target_dir)
            for path in paths:
                file_to_copy = path if path.startswith("/") else os.path.join(root_folder, path)
                for file_path in glob.glob(file_to_copy):
                    name = os.path.join(target_dir, file_path.split(os.path.sep)[-1])
                    if os.path.isdir(file_path):
                        cp_r(file_path, name)
                    else:
                        shutil.copyfile(file_path, name)

        if exclude_func:
            for dirpath, folders, files in os.walk(tmp_dir):
                for name in list(folders) + list(files):
                    full_name = os.path.join(dirpath, name)
                    relative = os.path.relpath(full_name, start=tmp_dir)
                    if exclude_func(relative):
                        rm_rf(full_name)

        # create zip file
        result = create_zip_file(tmp_dir, get_content=get_content)
        return result


def create_zip_file(
    file_path: str,
    zip_file: str = None,
    get_content: bool = False,
    content_root: str = None,
    mode: Literal["r", "w", "x", "a"] = "w",
):
    """
    Creates a zipfile to the designated file_path.

    By default, a new zip file is created but the mode parameter can be used to append to an existing zip file
    """
    base_dir = file_path
    if not os.path.isdir(file_path):
        base_dir = tempfile.mkdtemp(prefix=ARCHIVE_DIR_PREFIX)
        shutil.copy(file_path, base_dir)
        TMP_FILES.append(base_dir)
    tmp_dir = tempfile.mkdtemp(prefix=ARCHIVE_DIR_PREFIX)
    full_zip_file = zip_file
    if not full_zip_file:
        zip_file_name = "archive.zip"
        full_zip_file = os.path.join(tmp_dir, zip_file_name)
    # special case where target folder is empty -> create empty zip file
    if is_empty_dir(base_dir):
        # see https://stackoverflow.com/questions/25195495/how-to-create-an-empty-zip-file#25195628
        content = (
            b"PK\x05\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        )
        if get_content:
            return content
        save_file(full_zip_file, content)
        return full_zip_file

    # TODO: using a different packaging method here also produces wildly different .zip package sizes
    if is_debian() and "PYTEST_CURRENT_TEST" not in os.environ:
        # todo: extend CLI with the new parameters
        create_zip_file_cli(source_path=file_path, base_dir=base_dir, zip_file=full_zip_file)
    else:
        create_zip_file_python(
            base_dir=base_dir, zip_file=full_zip_file, mode=mode, content_root=content_root
        )
    if not get_content:
        TMP_FILES.append(tmp_dir)
        return full_zip_file
    with open(full_zip_file, "rb") as file_obj:
        zip_file_content = file_obj.read()
    rm_rf(tmp_dir)
    return zip_file_content


# TODO: make the `client` parameter mandatory to enforce proper xaccount access
def create_lambda_function(
    func_name,
    zip_file=None,
    event_source_arn=None,
    handler_file=None,
    handler=None,
    starting_position=None,
    runtime=None,
    envvars=None,
    tags=None,
    libs=None,
    delete=False,
    layers=None,
    client=None,
    role=None,
    timeout=None,
    region_name=None,
    s3_client=None,
    **kwargs,
):
    """Utility method to create a new function via the Lambda API
    CAVEAT: Does NOT wait until the function is ready/active. The fixture create_lambda_function waits until ready.
    """
    if envvars is None:
        envvars = {}
    if tags is None:
        tags = {}
    if libs is None:
        libs = []

    starting_position = starting_position or LAMBDA_DEFAULT_STARTING_POSITION
    runtime = runtime or LAMBDA_DEFAULT_RUNTIME
    client = client or connect_to(region_name=region_name).lambda_

    # load zip file content if handler_file is specified
    if not zip_file and handler_file:
        file_content = load_file(handler_file) if os.path.exists(handler_file) else handler_file
        if libs or not handler:
            zip_file = create_lambda_archive(
                file_content,
                libs=libs,
                get_content=True,
                runtime=runtime or LAMBDA_DEFAULT_RUNTIME,
            )
        else:
            zip_file = create_zip_file(handler_file, get_content=True)

    handler = handler or LAMBDA_DEFAULT_HANDLER

    if delete:
        try:
            # Delete function if one already exists
            client.delete_function(FunctionName=func_name)
        except Exception:
            pass

    lambda_code = {"ZipFile": zip_file}
    if len(zip_file) > MAX_LAMBDA_ARCHIVE_UPLOAD_SIZE:
        s3 = s3_client or connect_externally_to().s3
        resource_utils.get_or_create_bucket(LAMBDA_ASSETS_BUCKET_NAME)
        asset_key = f"{short_uid()}.zip"
        s3.upload_fileobj(
            Fileobj=io.BytesIO(zip_file), Bucket=LAMBDA_ASSETS_BUCKET_NAME, Key=asset_key
        )
        lambda_code = {"S3Bucket": LAMBDA_ASSETS_BUCKET_NAME, "S3Key": asset_key}

    # create function
    additional_kwargs = kwargs
    kwargs = {
        "FunctionName": func_name,
        "Runtime": runtime,
        "Handler": handler,
        "Role": role or LAMBDA_TEST_ROLE.format(account_id=get_aws_account_id()),
        "Code": lambda_code,
        "Timeout": timeout or LAMBDA_TIMEOUT_SEC,
        "Environment": dict(Variables=envvars),
        "Tags": tags,
    }
    kwargs.update(additional_kwargs)
    if layers:
        kwargs["Layers"] = layers
    create_func_resp = client.create_function(**kwargs)

    resp = {
        "CreateFunctionResponse": create_func_resp,
        "CreateEventSourceMappingResponse": None,
    }

    # create event source mapping
    if event_source_arn:
        resp["CreateEventSourceMappingResponse"] = client.create_event_source_mapping(
            FunctionName=func_name,
            EventSourceArn=event_source_arn,
            StartingPosition=starting_position,
        )

    return resp


def connect_api_gateway_to_http_with_lambda_proxy(
    gateway_name,
    target_uri,
    stage_name=None,
    methods=None,
    path=None,
    auth_type=None,
    auth_creator_func=None,
    http_method=None,
    client=None,
):
    if methods is None:
        methods = []
    if not methods:
        methods = ["GET", "POST", "DELETE"]
    if not path:
        path = "/"
    stage_name = stage_name or "test"
    resources = {}
    resource_path = path.lstrip("/")
    resources[resource_path] = []

    for method in methods:
        int_meth = http_method or method
        resources[resource_path].append(
            {
                "httpMethod": method,
                "authorizationType": auth_type,
                "authorizerId": None,
                "integrations": [{"type": "AWS_PROXY", "uri": target_uri, "httpMethod": int_meth}],
            }
        )
    return resource_utils.create_api_gateway(
        name=gateway_name,
        resources=resources,
        stage_name=stage_name,
        auth_creator_func=auth_creator_func,
        client=client,
    )


def create_lambda_api_gateway_integration(
    gateway_name,
    func_name,
    handler_file,
    lambda_client,
    methods=None,
    path=None,
    runtime=None,
    stage_name=None,
    auth_type=None,
    auth_creator_func=None,
):
    if methods is None:
        methods = []
    path = path or "/test"
    auth_type = auth_type or "REQUEST"
    stage_name = stage_name or "test"

    # create Lambda
    zip_file = create_lambda_archive(handler_file, get_content=True, runtime=runtime)
    func_arn = create_lambda_function(
        func_name=func_name, zip_file=zip_file, runtime=runtime, client=lambda_client
    )["CreateFunctionResponse"]["FunctionArn"]
    target_arn = arns.apigateway_invocations_arn(func_arn, TEST_AWS_REGION_NAME)

    # connect API GW to Lambda
    result = connect_api_gateway_to_http_with_lambda_proxy(
        gateway_name,
        target_arn,
        stage_name=stage_name,
        path=path,
        methods=methods,
        auth_type=auth_type,
        auth_creator_func=auth_creator_func,
    )
    return result


def assert_objects(asserts, all_objects):
    if type(asserts) is not list:
        asserts = [asserts]
    for obj in asserts:
        assert_object(obj, all_objects)


def assert_object(expected_object, all_objects):
    # for Python 3 compatibility
    dict_values = type({}.values())
    if isinstance(all_objects, dict_values):
        all_objects = list(all_objects)
    # wrap single item in an array
    if type(all_objects) is not list:
        all_objects = [all_objects]
    found = find_object(expected_object, all_objects)
    if not found:
        raise Exception("Expected object not found: %s in list %s" % (expected_object, all_objects))


def find_object(expected_object, object_list):
    for obj in object_list:
        if isinstance(obj, list):
            found = find_object(expected_object, obj)
            if found:
                return found

        all_ok = True
        if obj != expected_object:
            if not isinstance(expected_object, dict):
                all_ok = False
            else:
                for k, v in expected_object.items():
                    if not find_recursive(k, v, obj):
                        all_ok = False
                        break
        if all_ok:
            return obj
    return None


def find_recursive(key, value, obj):
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == key and v == value:
                return True
            if find_recursive(key, value, v):
                return True
    elif isinstance(obj, list):
        for o in obj:
            if find_recursive(key, value, o):
                return True
    else:
        return False


def start_http_server(
    test_port: int = None, invocations: List = None, invocation_handler: Callable = None
) -> Tuple[int, List, FuncThread]:
    # Note: leave imports here to avoid import errors (e.g., "flask") for CLI commands
    from localstack.services.generic_proxy import ProxyListener
    from localstack.services.infra import start_proxy

    class TestListener(ProxyListener):
        def forward_request(self, **kwargs):
            if invocation_handler:
                kwargs = invocation_handler(**kwargs)
            invocations.append(kwargs)
            return 200

    test_port = test_port or get_free_tcp_port()
    invocations = invocations or []
    proxy = start_proxy(test_port, update_listener=TestListener())
    return test_port, invocations, proxy


def list_all_s3_objects(s3_client):
    return map_all_s3_objects(s3_client=s3_client).values()


def delete_all_s3_objects(s3_client, buckets: str | List[str]):
    buckets = ensure_list(buckets)
    for bucket in buckets:
        keys = all_s3_object_keys(s3_client, bucket)
        deletes = [{"Key": key} for key in keys]
        if deletes:
            s3_client.delete_objects(Bucket=bucket, Delete={"Objects": deletes})


def download_s3_object(s3_client, bucket, path):
    with tempfile.SpooledTemporaryFile() as tmpfile:
        s3_client.download_fileobj(bucket, path, tmpfile)
        tmpfile.seek(0)
        result = tmpfile.read()
        try:
            result = to_str(result)
        except Exception:
            pass
        return result


def all_s3_object_keys(s3_client, bucket: str) -> List[str]:
    response = s3_client.list_objects_v2(Bucket=bucket)
    keys = [obj["Key"] for obj in response.get("Contents", [])]
    return keys


def map_all_s3_objects(
    s3_client, to_json: bool = True, buckets: str | List[str] = None
) -> Dict[str, Any]:
    result = {}
    buckets = ensure_list(buckets)
    if not buckets:
        # get all buckets
        response = s3_client.list_buckets()
        buckets = [b["Name"] for b in response["Buckets"]]

    for bucket in buckets:
        response = s3_client.list_objects_v2(Bucket=bucket)
        objects = [obj["Key"] for obj in response.get("Contents", [])]
        for key in objects:
            value = download_s3_object(s3_client, bucket, key)
            try:
                if to_json:
                    value = json.loads(value)
                separator = "" if key.startswith("/") else "/"
                result[f"{bucket}{separator}{key}"] = value
            except Exception:
                # skip non-JSON or binary objects
                pass
    return result


def send_describe_dynamodb_ttl_request(table_name):
    return send_dynamodb_request("", "DescribeTimeToLive", json.dumps({"TableName": table_name}))


def send_update_dynamodb_ttl_request(table_name, ttl_status):
    return send_dynamodb_request(
        "",
        "UpdateTimeToLive",
        json.dumps(
            {
                "TableName": table_name,
                "TimeToLiveSpecification": {
                    "AttributeName": "ExpireItem",
                    "Enabled": ttl_status,
                },
            }
        ),
    )


def send_dynamodb_request(path, action, request_body):
    headers = {
        "Host": "dynamodb.amazonaws.com",
        "x-amz-target": "DynamoDB_20120810.{}".format(action),
        "Authorization": aws_stack.mock_aws_request_headers("dynamodb")["Authorization"],
    }
    url = f"{config.service_url('dynamodb')}/{path}"
    return requests.put(url, data=request_body, headers=headers, verify=False)


def get_lambda_log_group_name(function_name):
    return "/aws/lambda/{}".format(function_name)


# TODO: make logs_client mandatory
def check_expected_lambda_log_events_length(
    expected_length, function_name, regex_filter=None, logs_client=None
):
    events = get_lambda_log_events(
        function_name, regex_filter=regex_filter, logs_client=logs_client
    )
    events = [line for line in events if line not in ["\x1b[0m", "\\x1b[0m"]]
    if len(events) != expected_length:
        print(
            "Invalid # of Lambda %s log events: %s / %s: %s"
            % (
                function_name,
                len(events),
                expected_length,
                [
                    event if len(event) < 1000 else f"{event[:1000]}... (truncated)"
                    for event in events
                ],
            )
        )
    assert len(events) == expected_length
    return events


def list_all_log_events(log_group_name: str, logs_client=None) -> List[Dict]:
    logs = logs_client or connect_to().logs
    return list_all_resources(
        lambda kwargs: logs.filter_log_events(logGroupName=log_group_name, **kwargs),
        last_token_attr_name="nextToken",
        list_attr_name="events",
    )


def get_lambda_log_events(
    function_name,
    delay_time=DEFAULT_GET_LOG_EVENTS_DELAY,
    regex_filter: Optional[str] = None,
    log_group=None,
    logs_client=None,
):
    def get_log_events(func_name, delay):
        time.sleep(delay)
        log_group_name = log_group or get_lambda_log_group_name(func_name)
        return list_all_log_events(log_group_name, logs_client)

    try:
        events = get_log_events(function_name, delay_time)
    except Exception as e:
        if "ResourceNotFoundException" in str(e):
            return []
        raise

    rs = []
    for event in events:
        raw_message = event["message"]
        if (
            not raw_message
            or "START" in raw_message
            or "END" in raw_message
            or "REPORT" in raw_message
            # necessary until tail is updated in docker images. See this PR:
            # http://git.savannah.gnu.org/gitweb/?p=coreutils.git;a=commitdiff;h=v8.24-111-g1118f32
            or "tail: unrecognized file system type" in raw_message
            or regex_filter
            and not re.search(regex_filter, raw_message)
        ):
            continue
        if raw_message in ["\x1b[0m", "\\x1b[0m"]:
            continue

        try:
            rs.append(json.loads(raw_message))
        except Exception:
            rs.append(raw_message)

    return rs


@contextmanager
def http_server(handler, host="127.0.0.1", port=None) -> str:
    """
    Create a temporary http server on a random port (or the specified port) with the given handler
    for the duration of the context manager.

    Example usage:

        def handler(request, data):
            print(request.method, request.path, data)

        with testutil.http_server(handler) as url:
            requests.post(url, json={"message": "hello"})
    """
    from localstack.utils.server.http2_server import run_server

    host = host
    port = port or get_free_tcp_port()
    thread = run_server(port, [host], handler=handler, asynchronous=True)
    url = f"http://{host}:{port}"
    assert poll_condition(
        lambda: is_port_open(port), timeout=5
    ), f"server on port {port} did not start"
    yield url
    thread.stop()


@contextmanager
def proxy_server(proxy_listener, host="127.0.0.1", port=None) -> str:
    """
    Create a temporary proxy server on a random port (or the specified port) with the given proxy listener
    for the duration of the context manager.
    """
    from localstack.services.generic_proxy import start_proxy_server

    host = host
    port = port or get_free_tcp_port()
    thread = start_proxy_server(port, bind_address=host, update_listener=proxy_listener)
    url = f"http://{host}:{port}"
    assert poll_condition(
        lambda: is_port_open(port), timeout=5
    ), f"server on port {port} did not start"
    yield url
    thread.stop()


def list_all_resources(
    page_function: Callable[[dict], Any],
    last_token_attr_name: str,
    list_attr_name: str,
    next_token_attr_name: Optional[str] = None,
) -> list:
    """
    List all available resources by loading all available pages using `page_function`.

    :type page_function: Callable
    :param page_function: callable function or lambda that accepts kwargs with next token
                          and returns the next results page

    :type last_token_attr_name: str
    :param last_token_attr_name: where to look for the last evaluated token

    :type list_attr_name: str
    :param list_attr_name: where to look for the list of items

    :type next_token_attr_name: Optional[str]
    :param next_token_attr_name: name of kwarg with the next token, default is the same as `last_token_attr_name`

    Example usage:

        all_log_groups = list_all_resources(
            lambda kwargs: logs.describe_log_groups(**kwargs),
            last_token_attr_name="nextToken",
            list_attr_name="logGroups"
        )

        all_records = list_all_resources(
            lambda kwargs: dynamodb.scan(**{**kwargs, **dynamodb_kwargs}),
            last_token_attr_name="LastEvaluatedKey",
            next_token_attr_name="ExclusiveStartKey",
            list_attr_name="Items"
        )
    """

    if next_token_attr_name is None:
        next_token_attr_name = last_token_attr_name

    result = None
    collected_items = []
    last_evaluated_token = None

    while not result or last_evaluated_token:
        kwargs = {next_token_attr_name: last_evaluated_token} if last_evaluated_token else {}
        result = page_function(kwargs)
        last_evaluated_token = result.get(last_token_attr_name)
        collected_items += result.get(list_attr_name, [])

    return collected_items


def response_arn_matches_partition(client, response_arn: str) -> bool:
    parsed_arn = arns.parse_arn(response_arn)
    return (
        client.meta.partition
        == boto3.session.Session().get_partition_for_region(parsed_arn["region"])
        and client.meta.partition == parsed_arn["partition"]
    )


def upload_file_to_bucket(s3_client, bucket_name, file_path, file_name=None):
    key = file_name or f"file-{short_uid()}"

    s3_client.upload_file(
        file_path,
        Bucket=bucket_name,
        Key=key,
    )

    domain = "amazonaws.com" if is_aws_cloud() else f"{LOCALHOST_HOSTNAME}:{config.EDGE_PORT}"
    url = f"https://{bucket_name}.s3.{domain}/{key}"

    return {"Bucket": bucket_name, "Key": key, "Url": url}
