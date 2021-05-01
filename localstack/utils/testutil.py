import os
import json
import glob
import tempfile
import time
import requests
import shutil
import zipfile
import importlib
from six import iteritems
from localstack.utils.aws import aws_stack
from localstack.constants import (
    LOCALSTACK_ROOT_FOLDER, LOCALSTACK_VENV_FOLDER, LAMBDA_TEST_ROLE, TEST_AWS_ACCOUNT_ID, ENV_INTERNAL_TEST_RUN)
from localstack.utils.common import (TMP_FILES, run, mkdir, to_str, load_file, save_file,
    is_alpine, chmod_r, get_free_tcp_port)
from localstack.services.generic_proxy import ProxyListener
from localstack.services.awslambda.lambda_utils import (
    get_handler_file_from_name, LAMBDA_DEFAULT_HANDLER, LAMBDA_DEFAULT_RUNTIME, LAMBDA_DEFAULT_STARTING_POSITION)

ARCHIVE_DIR_PREFIX = 'lambda.archive.'
DEFAULT_GET_LOG_EVENTS_DELAY = 3
LAMBDA_TIMEOUT_SEC = 6


def is_local_test_mode():
    """ Whether we are running in the context of our local integration tests. """
    return bool(os.environ.get(ENV_INTERNAL_TEST_RUN))


def copy_dir(source, target):
    if is_alpine():
        # Using the native command can be an order of magnitude faster on Travis-CI
        return run('cp -r %s %s' % (source, target))
    shutil.copytree(source, target)


def rm_dir(dir):
    if is_alpine():
        # Using the native command can be an order of magnitude faster on Travis-CI
        return run('rm -r %s' % dir)
    shutil.rmtree(dir)


def create_lambda_archive(script, get_content=False, libs=[], runtime=None, file_name=None):
    """ Utility method to create a Lambda function archive """
    runtime = runtime or LAMBDA_DEFAULT_RUNTIME
    tmp_dir = tempfile.mkdtemp(prefix=ARCHIVE_DIR_PREFIX)
    TMP_FILES.append(tmp_dir)
    file_name = file_name or get_handler_file_from_name(LAMBDA_DEFAULT_HANDLER, runtime=runtime)
    script_file = os.path.join(tmp_dir, file_name)
    if os.path.sep in script_file:
        mkdir(os.path.dirname(script_file))
        # create __init__.py files along the path to allow Python imports
        path = file_name.split(os.path.sep)
        for i in range(1, len(path)):
            save_file(os.path.join(tmp_dir, *(path[:i] + ['__init__.py'])), '')
    save_file(script_file, script)
    chmod_r(script_file, 0o777)
    # copy libs
    for lib in libs:
        paths = [lib, '%s.py' % lib]
        try:
            module = importlib.import_module(lib)
            paths.append(module.__file__)
        except Exception:
            pass
        target_dir = tmp_dir
        root_folder = os.path.join(LOCALSTACK_VENV_FOLDER, 'lib/python*/site-packages')
        if lib == 'localstack':
            paths = ['localstack/*.py', 'localstack/utils']
            root_folder = LOCALSTACK_ROOT_FOLDER
            target_dir = os.path.join(tmp_dir, lib)
            mkdir(target_dir)
        for path in paths:
            file_to_copy = path if path.startswith('/') else os.path.join(root_folder, path)
            for file_path in glob.glob(file_to_copy):
                name = os.path.join(target_dir, file_path.split(os.path.sep)[-1])
                if os.path.isdir(file_path):
                    copy_dir(file_path, name)
                else:
                    shutil.copyfile(file_path, name)

    # create zip file
    result = create_zip_file(tmp_dir, get_content=get_content)
    return result


def delete_lambda_function(name):
    client = aws_stack.connect_to_service('lambda')
    client.delete_function(FunctionName=name)


def create_zip_file_cli(source_path, base_dir, zip_file):
    # Using the native zip command can be an order of magnitude faster on Travis-CI
    source = '*' if source_path == base_dir else os.path.basename(source_path)
    command = 'cd %s; zip -r %s %s' % (base_dir, zip_file, source)
    run(command)


def create_zip_file_python(source_path, base_dir, zip_file):
    with zipfile.ZipFile(zip_file, 'w') as zip_file:
        for root, dirs, files in os.walk(base_dir):
            for name in files:
                full_name = os.path.join(root, name)
                relative = root[len(base_dir):].lstrip(os.path.sep)
                dest = os.path.join(relative, name)
                zip_file.write(full_name, dest)


def create_zip_file(file_path, zip_file=None, get_content=False):
    base_dir = file_path
    if not os.path.isdir(file_path):
        base_dir = tempfile.mkdtemp(prefix=ARCHIVE_DIR_PREFIX)
        shutil.copy(file_path, base_dir)
        TMP_FILES.append(base_dir)
    tmp_dir = tempfile.mkdtemp(prefix=ARCHIVE_DIR_PREFIX)
    full_zip_file = zip_file
    if not full_zip_file:
        zip_file_name = 'archive.zip'
        full_zip_file = os.path.join(tmp_dir, zip_file_name)
    # create zip file
    if is_alpine():
        create_zip_file_cli(file_path, base_dir, zip_file=full_zip_file)
    else:
        create_zip_file_python(file_path, base_dir, zip_file=full_zip_file)
    if not get_content:
        TMP_FILES.append(tmp_dir)
        return full_zip_file
    zip_file_content = None
    with open(full_zip_file, 'rb') as file_obj:
        zip_file_content = file_obj.read()
    rm_dir(tmp_dir)
    return zip_file_content


def create_lambda_function(func_name, zip_file=None, event_source_arn=None, handler_file=None,
        handler=None, starting_position=None, runtime=None, envvars={},
        tags={}, libs=[], delete=False, layers=None, **kwargs):
    """Utility method to create a new function via the Lambda API"""

    starting_position = starting_position or LAMBDA_DEFAULT_STARTING_POSITION
    runtime = runtime or LAMBDA_DEFAULT_RUNTIME
    client = aws_stack.connect_to_service('lambda')

    # load zip file content if handler_file is specified
    if not zip_file and handler_file:
        file_content = load_file(handler_file) if os.path.exists(handler_file) else handler_file
        if libs or not handler:
            zip_file = create_lambda_archive(file_content, libs=libs,
                get_content=True, runtime=runtime or LAMBDA_DEFAULT_RUNTIME)
        else:
            zip_file = create_zip_file(handler_file, get_content=True)

    handler = handler or LAMBDA_DEFAULT_HANDLER

    if delete:
        try:
            # Delete function if one already exists
            client.delete_function(FunctionName=func_name)
        except Exception:
            pass

    # create function
    additional_kwargs = kwargs
    kwargs = {
        'FunctionName': func_name,
        'Runtime': runtime,
        'Handler': handler,
        'Role': LAMBDA_TEST_ROLE,
        'Code': {
            'ZipFile': zip_file
        },
        'Timeout': LAMBDA_TIMEOUT_SEC,
        'Environment': dict(Variables=envvars),
        'Tags': tags
    }
    kwargs.update(additional_kwargs)
    if layers:
        kwargs['Layers'] = layers
    create_func_resp = client.create_function(**kwargs)

    resp = {
        'CreateFunctionResponse': create_func_resp,
        'CreateEventSourceMappingResponse': None
    }

    # create event source mapping
    if event_source_arn:
        resp['CreateEventSourceMappingResponse'] = client.create_event_source_mapping(
            FunctionName=func_name,
            EventSourceArn=event_source_arn,
            StartingPosition=starting_position
        )

    return resp


def connect_api_gateway_to_http_with_lambda_proxy(gateway_name, target_uri,
        stage_name=None, methods=[], path=None, auth_type=None, http_method=None):
    if not methods:
        methods = ['GET', 'POST', 'DELETE']
    if not path:
        path = '/'
    stage_name = stage_name or 'test'
    resources = {}
    resource_path = path.lstrip('/')
    resources[resource_path] = []
    for method in methods:
        int_meth = http_method or method
        resources[resource_path].append({
            'httpMethod': method,
            'authorizationType': auth_type,
            'integrations': [{
                'type': 'AWS_PROXY',
                'uri': target_uri,
                'httpMethod': int_meth
            }]
        })
    return aws_stack.create_api_gateway(
        name=gateway_name,
        resources=resources,
        stage_name=stage_name
    )


def create_lambda_api_gateway_integration(gateway_name, func_name, handler_file,
        methods=[], path=None, runtime=None, stage_name=None, auth_type=None):
    methods = methods or ['GET', 'POST']
    path = path or '/test'
    auth_type = auth_type or 'REQUEST'
    stage_name = stage_name or 'test'

    # create Lambda
    zip_file = create_lambda_archive(handler_file, get_content=True, runtime=runtime)
    create_lambda_function(func_name=func_name, zip_file=zip_file, runtime=runtime)
    func_arn = aws_stack.lambda_function_arn(func_name)
    target_arn = aws_stack.apigateway_invocations_arn(func_arn)

    # connect API GW to Lambda
    result = connect_api_gateway_to_http_with_lambda_proxy(
        gateway_name, target_arn, stage_name=stage_name, path=path, auth_type=auth_type)
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
        raise Exception('Expected object not found: %s in list %s' % (expected_object, all_objects))


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
                for k, v in iteritems(expected_object):
                    if not find_recursive(k, v, obj):
                        all_ok = False
                        break
        if all_ok:
            return obj
    return None


def find_recursive(key, value, obj):
    if isinstance(obj, dict):
        for k, v in iteritems(obj):
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


def start_http_server(test_port=None, invocations=None):
    from localstack.services.infra import start_proxy

    class TestListener(ProxyListener):
        def forward_request(self, **kwargs):
            invocations.append(kwargs)
            return 200

    test_port = test_port or get_free_tcp_port()
    invocations = invocations or []
    proxy = start_proxy(test_port, update_listener=TestListener())
    return test_port, invocations, proxy


def list_all_s3_objects():
    return map_all_s3_objects().values()


def delete_all_s3_objects(buckets):
    s3_client = aws_stack.connect_to_service('s3')
    buckets = buckets if isinstance(buckets, list) else [buckets]
    for bucket in buckets:
        keys = all_s3_object_keys(bucket)
        deletes = [{'Key': key} for key in keys]
        if deletes:
            s3_client.delete_objects(Bucket=bucket, Delete={'Objects': deletes})


def download_s3_object(s3, bucket, path):
    with tempfile.SpooledTemporaryFile() as tmpfile:
        s3.Bucket(bucket).download_fileobj(path, tmpfile)
        tmpfile.seek(0)
        result = tmpfile.read()
        try:
            result = to_str(result)
        except Exception:
            pass
        return result


def all_s3_object_keys(bucket):
    s3_client = aws_stack.connect_to_resource('s3')
    bucket = s3_client.Bucket(bucket) if isinstance(bucket, str) else bucket
    keys = [key for key in bucket.objects.all()]
    return keys


def map_all_s3_objects(to_json=True, buckets=None):
    s3_client = aws_stack.connect_to_resource('s3')
    result = {}
    buckets = buckets if not buckets or isinstance(buckets, list) else [buckets]
    buckets = [s3_client.Bucket(b) for b in buckets] if buckets else s3_client.buckets.all()
    for bucket in buckets:
        for key in bucket.objects.all():
            value = download_s3_object(s3_client, key.bucket_name, key.key)
            try:
                if to_json:
                    value = json.loads(value)
                key = '%s%s%s' % (key.bucket_name, '' if key.key.startswith('/') else '/', key.key)
                result[key] = value
            except Exception:
                # skip non-JSON or binary objects
                pass
    return result


def get_sample_arn(service, resource):
    return 'arn:aws:%s:%s:%s:%s' % (service, aws_stack.get_region(), TEST_AWS_ACCOUNT_ID, resource)


def send_describe_dynamodb_ttl_request(table_name):
    return send_dynamodb_request('', 'DescribeTimeToLive', json.dumps({'TableName': table_name}))


def send_update_dynamodb_ttl_request(table_name, ttl_status):
    return send_dynamodb_request('', 'UpdateTimeToLive', json.dumps({
        'TableName': table_name,
        'TimeToLiveSpecification': {
            'AttributeName': 'ExpireItem',
            'Enabled': ttl_status
        }
    }))


def send_dynamodb_request(path, action, request_body):
    headers = {
        'Host': 'dynamodb.amazonaws.com',
        'x-amz-target': 'DynamoDB_20120810.{}'.format(action),
        'Authorization': aws_stack.mock_aws_request_headers('dynamodb')['Authorization']
    }
    url = '{}/{}'.format(os.getenv('TEST_DYNAMODB_URL'), path)
    return requests.put(url, data=request_body, headers=headers, verify=False)


def create_sqs_queue(queue_name):
    """Utility method to create a new queue via SQS API"""

    client = aws_stack.connect_to_service('sqs')

    # create queue
    queue_url = client.create_queue(QueueName=queue_name)['QueueUrl']

    # get the queue arn
    queue_arn = client.get_queue_attributes(
        QueueUrl=queue_url,
        AttributeNames=['QueueArn'],
    )['Attributes']['QueueArn']

    return {
        'QueueUrl': queue_url,
        'QueueArn': queue_arn,
    }


def get_lambda_log_group_name(function_name):
    return '/aws/lambda/{}'.format(function_name)


def check_expected_lambda_log_events_length(expected_length, function_name):
    events = get_lambda_log_events(function_name)
    events = [line for line in events if line not in ['\x1b[0m', '\\x1b[0m']]
    if len(events) != expected_length:
        print('Invalid # of Lambda %s log events: %s / %s: %s' % (function_name, len(events), expected_length, events))
    assert len(events) == expected_length
    return events


def get_lambda_log_events(function_name, delay_time=DEFAULT_GET_LOG_EVENTS_DELAY):
    def get_log_events(function_name, delay_time):
        time.sleep(delay_time)

        logs = aws_stack.connect_to_service('logs')
        log_group_name = get_lambda_log_group_name(function_name)
        rs = logs.filter_log_events(logGroupName=log_group_name)

        return rs['events']

    try:
        events = get_log_events(function_name, delay_time)
    except Exception as e:
        if 'ResourceNotFoundException' in str(e):
            return []
        raise

    rs = []
    for event in events:
        raw_message = event['message']
        if not raw_message or 'START' in raw_message or 'END' in raw_message or 'REPORT' in raw_message:
            continue
        if raw_message in ['\x1b[0m', '\\x1b[0m']:
            continue

        try:
            rs.append(json.loads(raw_message))
        except Exception:
            rs.append(raw_message)

    return rs
