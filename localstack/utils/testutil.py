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
    LOCALSTACK_ROOT_FOLDER, LOCALSTACK_VENV_FOLDER, LAMBDA_TEST_ROLE, TEST_AWS_ACCOUNT_ID)
from localstack.utils.common import TMP_FILES, run, mkdir, to_str, load_file, save_file, is_alpine
from localstack.services.awslambda.lambda_api import (
    get_handler_file_from_name, LAMBDA_DEFAULT_HANDLER, LAMBDA_DEFAULT_RUNTIME, LAMBDA_DEFAULT_STARTING_POSITION)

ARCHIVE_DIR_PREFIX = 'lambda.archive.'
DEFAULT_GET_LOG_EVENTS_DELAY = 3
LAMBDA_TIMEOUT_SEC = 6


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


def create_zip_file(file_path, get_content=False):
    base_dir = file_path
    if not os.path.isdir(file_path):
        base_dir = tempfile.mkdtemp(prefix=ARCHIVE_DIR_PREFIX)
        shutil.copy(file_path, base_dir)
        TMP_FILES.append(base_dir)
    tmp_dir = tempfile.mkdtemp(prefix=ARCHIVE_DIR_PREFIX)
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
        handler=LAMBDA_DEFAULT_HANDLER, starting_position=None, runtime=None, envvars={},
        tags={}, libs=[], delete=False, layers=None, **kwargs):
    """Utility method to create a new function via the Lambda API"""

    starting_position = starting_position or LAMBDA_DEFAULT_STARTING_POSITION
    runtime = runtime or LAMBDA_DEFAULT_RUNTIME
    client = aws_stack.connect_to_service('lambda')

    # load zip file content if handler_file is specified
    if not zip_file and handler_file:
        zip_file = create_lambda_archive(load_file(handler_file), libs=libs,
            get_content=True, runtime=runtime or LAMBDA_DEFAULT_RUNTIME)

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


def list_all_s3_objects():
    return map_all_s3_objects().values()


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


def map_all_s3_objects(to_json=True, buckets=None):
    s3_client = aws_stack.get_s3_client()
    result = {}
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
        'authorization': 'some_token'
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


def get_lambda_log_events(function_name, delay_time=DEFAULT_GET_LOG_EVENTS_DELAY):
    def get_log_events(function_name, delay_time):
        time.sleep(delay_time)

        logs = aws_stack.connect_to_service('logs')
        rs = logs.filter_log_events(
            logGroupName=get_lambda_log_group_name(function_name)
        )

        return rs['events']

    events = get_log_events(function_name, delay_time)
    rs = []
    for event in events:
        raw_message = event['message']
        if not raw_message or 'START' in raw_message or 'END' in raw_message or 'REPORT' in raw_message:
            continue

        try:
            rs.append(json.loads(raw_message))
        except Exception:
            rs.append(raw_message)

    return rs
